use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use dashmap::{DashMap, DashSet};
use futures_channel::mpsc;
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tap::TapFallible;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{error, info, instrument};

use super::encrypt::EncryptActor;
use super::message::UdpMessage as Message;
use super::message::{EncryptMessage, TunMessage};
use super::public_key::PublicKey;
use crate::protocol::Frame;

#[derive(Debug)]
pub struct UdpActor {
    mailbox_sender: Sender<Message>,
    mailbox: Receiver<Message>,
    connected_peers: Arc<DashMap<SocketAddr, Sender<EncryptMessage>>>,
    tun_sender: Sender<TunMessage>,

    udp_socket: Arc<UdpSocket>,
    read_task: JoinHandle<()>,

    listen_addr: SocketAddr,
    local_private_key: Bytes,
    heartbeat_interval: Duration,
    remote_public_keys: Arc<DashSet<PublicKey>>,
}

impl UdpActor {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        connected_peers: Arc<DashMap<SocketAddr, Sender<EncryptMessage>>>,
        tun_sender: Sender<TunMessage>,
        listen_addr: SocketAddr,
        local_private_key: Bytes,
        heartbeat_interval: Duration,
        remote_public_keys: Arc<DashSet<PublicKey>>,
    ) -> anyhow::Result<Self> {
        let (udp_socket, read_task) = Self::start(listen_addr, mailbox_sender.clone()).await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            connected_peers,
            tun_sender,
            udp_socket,
            read_task,
            listen_addr,
            local_private_key,
            heartbeat_interval,
            remote_public_keys,
        })
    }

    async fn start(
        listen_addr: SocketAddr,
        sender: Sender<Message>,
    ) -> anyhow::Result<(Arc<UdpSocket>, JoinHandle<()>)> {
        let udp_socket = UdpSocket::bind(listen_addr)
            .await
            .tap_err(|err| error!(%err, %listen_addr, "bind udp socket failed"))?;
        let udp_socket = Arc::new(udp_socket);

        info!(%listen_addr, "bind udp socket done");

        let read_task = {
            let sender = sender.clone();
            let udp_socket = udp_socket.clone();

            tokio::spawn(Self::read_from_udp(udp_socket, sender))
        };

        Ok((udp_socket, read_task))
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        self.read_task.abort();

        let (udp_socket, read_task) =
            Self::start(self.listen_addr, self.mailbox_sender.clone()).await?;
        self.udp_socket = udp_socket;
        self.read_task = read_task;

        Ok(())
    }

    async fn read_from_udp(udp_socket: Arc<UdpSocket>, mut sender: Sender<Message>) {
        let mut buf = BytesMut::with_capacity(4096);
        loop {
            buf.clear();

            let (packet, from) = match udp_socket.recv_buf_from(&mut buf).await {
                Err(err) => {
                    error!(%err, "receive udp socket failed");

                    let _ = sender.send(Message::Packet(Err(err))).await;

                    return;
                }

                Ok((n, from)) => (buf.copy_to_bytes(n), from),
            };

            if let Err(err) = sender.send(Message::Packet(Ok((packet, from)))).await {
                error!(%err, "send packet failed");

                return;
            }
        }
    }

    pub async fn run(&mut self) {
        loop {
            if let Err(err) = self.run_circle().await {
                error!(%err, "udp actor run circle failed, need restart");

                loop {
                    match self.restart().await {
                        Err(err) => {
                            error!(%err, "udp actor restart failed");
                        }

                        Ok(_) => {
                            info!("udp actor restart done");

                            break;
                        }
                    }
                }
            }
        }
    }

    #[instrument(err)]
    async fn run_circle(&mut self) -> anyhow::Result<()> {
        let message = match self.mailbox.next().await {
            None => {
                error!("receive message from mailbox failed");

                return Err(anyhow::anyhow!("receive message from mailbox failed"));
            }

            Some(message) => message,
        };

        match message {
            Message::Frame { frame, to } => {
                let packet = frame.encode_to_vec();

                self.udp_socket
                    .send_to(&packet, to)
                    .await
                    .tap_err(|err| error!(%err, %to, "send packet failed"))?;

                info!(%to, "send packet done");

                Ok(())
            }

            Message::Packet(Err(err)) => {
                error!(%err, "receive packet failed");

                Err(err.into())
            }

            Message::Packet(Ok((packet, from))) => {
                let frame = match Frame::decode(packet) {
                    Err(err) => {
                        error!(%err, "decode packet failed");

                        return Ok(());
                    }

                    Ok(frame) => frame,
                };

                info!("decode packet done");

                match self.connected_peers.get(&from) {
                    Some(sender_ref) => {
                        let mut sender = sender_ref.clone();
                        drop(sender_ref);

                        if let Err(err) = sender.send(EncryptMessage::Frame { frame, from }).await {
                            error!(%err, "send frame to encrypt actor failed");

                            return Err(err.into());
                        }

                        info!(%from, "send frame to encrypt actor done");

                        Ok(())
                    }

                    None => {
                        let (mailbox_sender, mailbox) = mpsc::channel(10);
                        match EncryptActor::new(
                            mailbox_sender.clone(),
                            mailbox,
                            self.mailbox_sender.clone(),
                            self.tun_sender.clone(),
                            self.local_private_key.clone(),
                            frame,
                            from,
                            self.heartbeat_interval,
                            &self.remote_public_keys,
                        ) {
                            Err(err) => {
                                error!(%err, "create encrypt actor failed");

                                Ok(())
                            }

                            Ok((mut encrypt_actor, response_frame)) => {
                                let response_packet = response_frame.encode_to_vec();

                                self.udp_socket
                                    .send_to(&response_packet, from)
                                    .await
                                    .tap_err(
                                        |err| error!(%err, %from, "send packet back failed"),
                                    )?;

                                info!(%from, "send packet back done");

                                self.connected_peers.insert(from, mailbox_sender);
                                let connected_peers = self.connected_peers.clone();

                                tokio::spawn(async move {
                                    let _ = encrypt_actor.run().await;

                                    connected_peers.remove(&from);
                                });

                                Ok(())
                            }
                        }
                    }
                }
            }
        }
    }
}
