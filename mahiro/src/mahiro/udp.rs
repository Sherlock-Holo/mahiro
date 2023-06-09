use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::StreamExt;
use prost::Message as _;
use tap::TapFallible;
use tokio::net::{self, ToSocketAddrs, UdpSocket};
use tokio::task::JoinHandle;
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
    read_task: JoinHandle<()>,
}

impl UdpActor {
    pub async fn new(
        encrypt_sender: Sender<EncryptMessage>,
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        remote_addr: impl ToSocketAddrs,
    ) -> anyhow::Result<Self> {
        let remote_addr = net::lookup_host(remote_addr)
            .await
            .tap_err(|err| error!(%err, "lookup host failed"))?
            .collect::<Vec<_>>();

        let (udp_socket, read_task) = Self::start(&remote_addr, mailbox_sender.clone()).await?;
        let udp_actor = Self {
            mailbox_sender,
            mailbox,
            encrypt_sender,
            remote_addr,
            udp_socket,
            read_task,
        };

        Ok(udp_actor)
    }

    async fn start(
        remote_addr: &[SocketAddr],
        sender: Sender<Message>,
    ) -> anyhow::Result<(Arc<UdpSocket>, JoinHandle<()>)> {
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .tap_err(|err| error!(%err, "bind udp socket failed"))?;
        udp_socket
            .connect(remote_addr)
            .await
            .tap_err(|err| error!(%err, ?remote_addr, "udp connect failed"))?;
        let udp_socket = Arc::new(udp_socket);
        let read_task = {
            let udp_socket = udp_socket.clone();
            tokio::spawn(Self::read_from_udp(udp_socket, sender))
        };

        Ok((udp_socket, read_task))
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        self.read_task.abort();

        let (udp_socket, read_task) =
            Self::start(&self.remote_addr, self.mailbox_sender.clone()).await?;
        self.udp_socket = udp_socket;
        self.read_task = read_task;

        Ok(())
    }

    async fn read_from_udp(udp_socket: Arc<UdpSocket>, sender: Sender<Message>) {
        let mut buf = BytesMut::with_capacity(1500 * 4);
        loop {
            buf.reserve(1500);

            let packet = match udp_socket.recv_buf(&mut buf).await {
                Err(err) => {
                    error!(%err, "receive udp socket failed");

                    let _ = sender.try_send(Message::Packet(Err(err)));

                    return;
                }

                Ok(_) => buf.split().freeze(),
            };

            match sender.try_send(Message::Packet(Ok(packet))) {
                Err(TrySendError::Full(_)) => {
                    warn!("encrypt actor mailbox full");
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
                error!(%err, "run circle failed, need restart");

                loop {
                    match self.restart().await {
                        Err(err) => {
                            error!(%err, "restart failed");
                        }

                        Ok(_) => {
                            info!("restart done");

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
                error!("get message from udp mailbox failed");

                return Err(anyhow::anyhow!("get message from mailbox failed"));
            }

            Some(message) => message,
        };

        match message {
            Message::Frame(frame) => {
                let frame_data = frame.encode_to_vec();

                self.udp_socket
                    .send(&frame_data)
                    .await
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

                match self.encrypt_sender.try_send(EncryptMessage::Frame(frame)) {
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
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use test_log::test;

    use super::*;
    use crate::cookie::generate_cookie;
    use crate::protocol::FrameType;

    #[test(tokio::test)]
    async fn test() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

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
        tokio::spawn(async move { udp_actor.run().await });

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

        let mut buf = vec![0; 4096];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        info!(%from, "get client udp addr");

        let receive_frame = Frame::decode(&buf[..n]).unwrap();

        assert_eq!(frame, receive_frame);

        let frame = Frame {
            cookie,
            r#type: FrameType::Handshake as _,
            nonce: 1,
            data: Bytes::from_static(b"world"),
        };

        server.send_to(&frame.encode_to_vec(), from).await.unwrap();

        let receive_frame = encrypt_mailbox.next().await.unwrap();
        let receive_frame = match receive_frame {
            EncryptMessage::Frame(receive_frame) => receive_frame,
            _ => panic!("other encrypt message"),
        };

        assert_eq!(frame, receive_frame);
    }
}
