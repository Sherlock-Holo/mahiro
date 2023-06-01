use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use prost::Message as _;
use ring_io::net::udp::UdpSocket;
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
        let udp_socket = Self::start(listen_addr).await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            peer_store,
            tun_sender,
            udp_socket,
            listen_addr,
            local_private_key,
            heartbeat_interval,
        })
    }

    async fn start(listen_addr: SocketAddr) -> anyhow::Result<Arc<UdpSocket>> {
        let udp_socket = UdpSocket::bind(listen_addr)
            .tap_err(|err| error!(%err, %listen_addr, "bind udp socket failed"))?;
        let udp_socket = Arc::new(udp_socket);

        info!(%listen_addr, "bind udp socket done");

        Ok(udp_socket)
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        let udp_socket = Self::start(self.listen_addr).await?;
        self.udp_socket = udp_socket;

        Ok(())
    }

    async fn read_from_udp(
        udp_socket: Arc<UdpSocket>,
        sender: Sender<Message>,
    ) -> anyhow::Result<()> {
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

                    return Err(anyhow::anyhow!("receive udp socket failed"));
                }

                Ok((_, from)) => (buf.split().freeze(), from),
            };

            match sender.try_send(Message::Packet(Ok((packet, from)))) {
                Err(TrySendError::Full(_)) => {
                    warn!("udp actor mailbox is full");
                }

                Err(err) => {
                    error!(%err, "send packet failed");

                    return Err(anyhow::anyhow!("send packet failed"));
                }

                Ok(_) => {}
            }
        }
    }

    pub async fn run(&mut self) {
        let mut tasks = FuturesUnordered::new();
        let task_count = available_parallelism()
            .unwrap_or(NonZeroUsize::new(4).unwrap())
            .get();
        loop {
            for _ in 0..task_count {
                let udp_socket = self.udp_socket.clone();
                let sender = self.mailbox_sender.clone();
                let task =
                    ring_io::spawn(async move { Self::read_from_udp(udp_socket, sender).await });
                tasks.push(task);
            }

            info!("start {task_count} udp reader done");

            for _ in 0..task_count {
                let udp_socket = self.udp_socket.clone();
                let mailbox_sender = self.mailbox_sender.clone();
                let tun_sender = self.tun_sender.clone();
                let mailbox = self.mailbox.clone();
                let peer_store = self.peer_store.clone();
                let local_private_key = self.local_private_key.clone();
                let heartbeat_interval = self.heartbeat_interval;

                let task = ring_io::spawn(Self::run_loop(
                    udp_socket,
                    mailbox_sender,
                    tun_sender,
                    mailbox,
                    peer_store,
                    local_private_key,
                    heartbeat_interval,
                ));
                tasks.push(task);
            }

            info!("start {task_count} udp writer done");

            while let Some(result) = tasks.next().await {
                if let Err(err) = result {
                    error!(%err, "udp actor inner stop with error");

                    break;
                }
            }

            tasks.clear();

            error!("udp actor inner stop, need restart");

            loop {
                match self.restart().await {
                    Err(err) => {
                        error!(%err, "udp actor inner restart failed");
                    }

                    Ok(_) => {
                        info!("udp actor inner restart done");

                        break;
                    }
                }
            }
        }
    }

    async fn run_loop(
        udp_socket: Arc<UdpSocket>,
        udp_mailbox_sender: Sender<Message>,
        tun_sender: Sender<TunMessage>,
        mut mailbox: Receiver<Message>,
        peer_store: PeerStore,
        local_private_key: Bytes,
        heartbeat_interval: Duration,
    ) -> anyhow::Result<()> {
        loop {
            Self::run_circle(
                &udp_socket,
                &udp_mailbox_sender,
                &tun_sender,
                &mut mailbox,
                &peer_store,
                &local_private_key,
                heartbeat_interval,
            )
            .await?;
        }
    }

    #[instrument(err, skip(mailbox))]
    async fn run_circle(
        udp_socket: &UdpSocket,
        udp_mailbox_sender: &Sender<Message>,
        tun_sender: &Sender<TunMessage>,
        mailbox: &mut Receiver<Message>,
        peer_store: &PeerStore,
        local_private_key: &Bytes,
        heartbeat_interval: Duration,
    ) -> anyhow::Result<()> {
        let message = match mailbox.next().await {
            None => {
                error!("receive message from mailbox failed");

                return Err(anyhow::anyhow!("receive message from mailbox failed"));
            }

            Some(message) => message,
        };

        match message {
            Message::Frame { frame, to } => {
                let packet = frame.encode_to_vec();

                udp_socket
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

                match peer_store.get_peer_info_by_cookie(&frame.cookie) {
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
                            udp_mailbox_sender.clone(),
                            tun_sender.clone(),
                            local_private_key.clone(),
                            frame,
                            heartbeat_interval,
                            peer_store,
                        ) {
                            Err(err) => {
                                error!(%err, "create encrypt actor failed");

                                Ok(())
                            }

                            Ok((mut encrypt_actor, response_frame)) => {
                                let response_packet = response_frame.encode_to_vec();

                                udp_socket.send_to(response_packet, from).await.0.tap_err(
                                    |err| error!(%err, %from, "send packet back failed"),
                                )?;

                                debug!(%from, "send packet back done");

                                // make sure next packet can find encrypt actor
                                peer_store.add_peer_info(cookie.clone(), from, mailbox_sender);

                                let peer_store = peer_store.clone();

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
