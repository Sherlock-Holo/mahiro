use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::StreamExt;
use prost::Message as _;
use ring_io::net::udp::UdpSocket;
use ring_io::runtime::Task;
use tap::TapFallible;
use tracing::{debug, error, info, instrument};
use tracing_log::log::warn;

use super::encrypt::EncryptActor;
use super::message::UdpMessage as Message;
use super::message::{EncryptMessage, TunMessage};
use super::peer_store::PeerStore;
use crate::protocol::Frame;
use crate::util::Receiver;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct UdpActor {
    mailbox_sender: Sender<Message>,
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    peer_store: PeerStore,
    tun_sender: Sender<TunMessage>,

    udp_socket: Arc<UdpSocket>,
    read_task: Option<Task<()>>,

    listen_addr: SocketAddr,
    #[derivative(Debug = "ignore")]
    local_private_key: Bytes,
    heartbeat_interval: Duration,
}

impl UdpActor {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        peer_store: PeerStore,
        tun_sender: Sender<TunMessage>,
        listen_addr: SocketAddr,
        local_private_key: Bytes,
        heartbeat_interval: Duration,
    ) -> anyhow::Result<Self> {
        let (udp_socket, read_task) = Self::start(listen_addr, mailbox_sender.clone()).await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            peer_store,
            tun_sender,
            udp_socket,
            read_task: Some(read_task),
            listen_addr,
            local_private_key,
            heartbeat_interval,
        })
    }

    async fn start(
        listen_addr: SocketAddr,
        sender: Sender<Message>,
    ) -> anyhow::Result<(Arc<UdpSocket>, Task<()>)> {
        let udp_socket = UdpSocket::bind(listen_addr)
            .tap_err(|err| error!(%err, %listen_addr, "bind udp socket failed"))?;
        let udp_socket = Arc::new(udp_socket);

        info!(%listen_addr, "bind udp socket done");

        let read_task = {
            let udp_socket = udp_socket.clone();

            ring_io::spawn(Self::read_from_udp(udp_socket, sender))
        };

        Ok((udp_socket, read_task))
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        self.read_task.take().unwrap().cancel().await;

        let (udp_socket, read_task) =
            Self::start(self.listen_addr, self.mailbox_sender.clone()).await?;
        self.udp_socket = udp_socket;
        self.read_task = Some(read_task);

        Ok(())
    }

    async fn read_from_udp(udp_socket: Arc<UdpSocket>, sender: Sender<Message>) {
        let mut buf = BytesMut::with_capacity(1500 * 4);
        loop {
            buf.reserve(1500);

            let result = udp_socket.recv_from(buf).await;
            buf = result.1;
            let result = result.0;
            let (packet, from) = match result {
                Err(err) => {
                    error!(%err, "receive udp socket failed");

                    let _ = sender.try_send(Message::Packet(Err(err)));

                    return;
                }

                Ok((_, from)) => (buf.split().freeze(), from),
            };

            match sender.try_send(Message::Packet(Ok((packet, from)))) {
                Err(TrySendError::Full(_)) => {
                    warn!("udp actor mailbox is full");
                }

                Err(err) => {
                    error!(%err, "send packet failed");

                    return;
                }

                Ok(_) => {}
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
                    .send_to(packet, to)
                    .await
                    .0
                    .tap_err(|err| error!(%err, %to, "send packet failed"))?;

                debug!(%to, "send packet done");

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

                debug!("decode packet done");

                match self.peer_store.get_peer_info_by_cookie(&frame.cookie) {
                    Some(peer_info) => {
                        match peer_info
                            .sender
                            .try_send(EncryptMessage::Frame { frame, from })
                        {
                            Err(TrySendError::Full(_)) => {
                                warn!("encrypt actor mailbox full");
                            }

                            Err(err) => {
                                error!(%err, "send frame to encrypt actor failed");

                                return Err(err.into());
                            }

                            Ok(_) => {}
                        }

                        debug!(%from, "send frame to encrypt actor done");

                        Ok(())
                    }

                    None => {
                        let cookie = frame.cookie.clone();
                        let (mailbox_sender, mailbox) = flume::bounded(64);
                        match EncryptActor::new(
                            mailbox_sender.clone(),
                            mailbox.into_stream(),
                            self.mailbox_sender.clone(),
                            self.tun_sender.clone(),
                            self.local_private_key.clone(),
                            frame,
                            self.heartbeat_interval,
                            &self.peer_store,
                        ) {
                            Err(err) => {
                                error!(%err, "create encrypt actor failed");

                                Ok(())
                            }

                            Ok((mut encrypt_actor, response_frame)) => {
                                let response_packet = response_frame.encode_to_vec();

                                self.udp_socket
                                    .send_to(response_packet, from)
                                    .await
                                    .0
                                    .tap_err(
                                        |err| error!(%err, %from, "send packet back failed"),
                                    )?;

                                debug!(%from, "send packet back done");

                                // make sure next packet can find encrypt actor
                                self.peer_store
                                    .add_peer_info(cookie.clone(), from, mailbox_sender);

                                let peer_store = self.peer_store.clone();

                                ring_io::spawn(async move {
                                    let _ = encrypt_actor.run().await;

                                    peer_store.remove_peer(&cookie);
                                })
                                .detach();

                                Ok(())
                            }
                        }
                    }
                }
            }
        }
    }
}
