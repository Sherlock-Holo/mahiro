use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread::available_parallelism;

use bytes::BytesMut;
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use prost::Message as _;
use ring_io::net;
use ring_io::net::udp::UdpSocket;
use tap::TapFallible;
use tracing::{debug, error, info, instrument, warn};

use super::message::EncryptMessage;
use super::message::UdpMessage as Message;
use crate::protocol::Frame;
use crate::util::Receiver;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct UdpActor {
    mailbox_sender: Sender<Message>,
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    encrypt_sender: Sender<EncryptMessage>,

    remote_addr: Vec<SocketAddr>,

    udp_socket: Arc<UdpSocket>,
}

impl UdpActor {
    pub async fn new<A>(
        encrypt_sender: Sender<EncryptMessage>,
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        remote_addr: A,
    ) -> anyhow::Result<Self>
    where
        A: ToSocketAddrs + Send + 'static,
        A::Iter: Send + 'static,
    {
        let remote_addr = net::to_socket_addrs(remote_addr)
            .await
            .tap_err(|err| error!(%err, "lookup host failed"))?
            .collect::<Vec<_>>();

        let udp_socket = Self::start(&remote_addr).await?;
        let udp_actor = Self {
            mailbox_sender,
            mailbox,
            encrypt_sender,
            remote_addr,
            udp_socket,
        };

        Ok(udp_actor)
    }

    async fn start(remote_addr: &[SocketAddr]) -> anyhow::Result<Arc<UdpSocket>> {
        let udp_socket = UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0).into())
            .tap_err(|err| error!(%err, "bind udp socket failed"))?;

        let mut last_err = None;
        for &remote_addr in remote_addr {
            match udp_socket.connect(remote_addr).await {
                Err(err) => {
                    last_err = Some(err);
                }

                Ok(_) => {
                    last_err.take();
                }
            }
        }
        if let Some(err) = last_err {
            error!(%err, ?remote_addr, "udp connect failed");

            return Err(err.into());
        }

        let udp_socket = Arc::new(udp_socket);

        Ok(udp_socket)
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        let udp_socket = Self::start(&self.remote_addr).await?;
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

            let result = udp_socket.recv(buf).await;
            buf = result.1;
            let result = result.0;
            let packet = match result {
                Err(err) => {
                    error!(%err, "receive udp socket failed");

                    let _ = sender.try_send(Message::Packet(Err(err)));

                    return Err(anyhow::anyhow!("receive udp socket failed"));
                }

                Ok(_) => buf.split().freeze(),
            };

            match sender.try_send(Message::Packet(Ok(packet))) {
                Err(TrySendError::Full(_)) => {
                    warn!("encrypt actor mailbox full");
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
                let mailbox = self.mailbox.clone();
                let udp_socket = self.udp_socket.clone();
                let encrypt_sender = self.encrypt_sender.clone();

                let task = ring_io::spawn(Self::run_loop(udp_socket, encrypt_sender, mailbox));
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
        encrypt_sender: Sender<EncryptMessage>,
        mut mailbox: Receiver<Message>,
    ) -> anyhow::Result<()> {
        loop {
            Self::run_circle(&udp_socket, &encrypt_sender, &mut mailbox).await?;
        }
    }

    #[instrument(err, skip(mailbox))]
    async fn run_circle(
        udp_socket: &UdpSocket,
        encrypt_sender: &Sender<EncryptMessage>,
        mailbox: &mut Receiver<Message>,
    ) -> anyhow::Result<()> {
        let message = match mailbox.next().await {
            None => {
                error!("get message from udp mailbox failed");

                return Err(anyhow::anyhow!("get message from mailbox failed"));
            }

            Some(message) => message,
        };

        match message {
            Message::Frame(frame) => {
                let frame_data = frame.encode_to_vec();

                udp_socket
                    .send(frame_data)
                    .await
                    .0
                    .tap_err(|err| error!(%err, "send frame data failed"))?;

                Ok(())
            }
            Message::Packet(Err(err)) => Err(err.into()),

            Message::Packet(Ok(packet)) => {
                let frame = match Frame::decode(packet) {
                    Err(err) => {
                        error!(%err, "decode packet failed");

                        return Ok(());
                    }

                    Ok(frame) => {
                        debug!("decode frame done");

                        frame
                    }
                };

                match encrypt_sender.try_send(EncryptMessage::Frame(frame)) {
                    Err(TrySendError::Full(_)) => {
                        warn!("encrypt actor mailbox is full");

                        Ok(())
                    }

                    Err(err) => {
                        error!(%err, "send frame to encrypt failed");

                        Err(err.into())
                    }

                    Ok(_) => Ok(()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket as StdUdpSocket;

    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use test_log::test;

    use super::*;
    use crate::cookie::generate_cookie;
    use crate::protocol::FrameType;

    #[test]
    fn test() {
        ring_io::block_on(async move {
            let server = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = server.local_addr().unwrap();
            let server = UdpSocket::from_std(server);

            let (encrypt_sender, encrypt_mailbox) = flume::bounded(10);
            let (mailbox_sender, mailbox) = flume::bounded(10);
            let mut udp_actor = UdpActor::new(
                encrypt_sender,
                mailbox_sender.clone(),
                mailbox.into_stream(),
                addr,
            )
            .await
            .unwrap();
            ring_io::spawn(async move { udp_actor.run().await }).detach();

            let mut encrypt_mailbox = encrypt_mailbox.into_stream();
            let mut mailbox_sender = mailbox_sender.into_sink();

            let cookie = generate_cookie();
            let frame = Frame {
                cookie: cookie.clone(),
                r#type: FrameType::Handshake as _,
                nonce: 0,
                data: Bytes::from_static(b"hello"),
            };

            mailbox_sender
                .send(Message::Frame(frame.clone()))
                .await
                .unwrap();

            let buf = vec![0; 4096];
            let (result, buf) = server.recv_from(buf).await;
            let (n, from) = result.unwrap();
            info!(%from, "get client udp addr");

            let receive_frame = Frame::decode(&buf[..n]).unwrap();

            assert_eq!(frame, receive_frame);

            let frame = Frame {
                cookie,
                r#type: FrameType::Handshake as _,
                nonce: 1,
                data: Bytes::from_static(b"world"),
            };

            server.send_to(frame.encode_to_vec(), from).await.0.unwrap();

            let receive_frame = encrypt_mailbox.next().await.unwrap();
            let receive_frame = match receive_frame {
                EncryptMessage::Frame(receive_frame) => receive_frame,
                _ => panic!("other encrypt message"),
            };

            assert_eq!(frame, receive_frame);
        })
    }
}
