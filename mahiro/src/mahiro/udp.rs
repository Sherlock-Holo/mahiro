use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tap::TapFallible;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{error, info, instrument};

use super::message::EncryptMessage;
use super::message::UdpMessage as Message;
use crate::protocol::Frame;

#[derive(Debug)]
pub struct UdpActor {
    mailbox_sender: Sender<Message>,
    mailbox: Receiver<Message>,
    encrypt_sender: Sender<EncryptMessage>,

    remote_addr: SocketAddr,

    udp_socket: Arc<UdpSocket>,
    read_task: JoinHandle<()>,
}

impl UdpActor {
    pub async fn new(
        encrypt_sender: Sender<EncryptMessage>,
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<Self> {
        let (udp_socket, read_task) = Self::start(remote_addr, mailbox_sender.clone()).await?;
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
        remote_addr: SocketAddr,
        sender: Sender<Message>,
    ) -> anyhow::Result<(Arc<UdpSocket>, JoinHandle<()>)> {
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .tap_err(|err| error!(%err, "bind udp socket failed"))?;
        udp_socket
            .connect(remote_addr)
            .await
            .tap_err(|err| error!(%err, %remote_addr, "udp connect failed"))?;
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
            Self::start(self.remote_addr, self.mailbox_sender.clone()).await?;
        self.udp_socket = udp_socket;
        self.read_task = read_task;

        Ok(())
    }

    async fn read_from_udp(udp_socket: Arc<UdpSocket>, mut sender: Sender<Message>) {
        let mut buf = BytesMut::with_capacity(4096);
        loop {
            buf.clear();

            let packet = match udp_socket.recv_buf(&mut buf).await {
                Err(err) => {
                    error!(%err, "receive udp socket failed");

                    let _ = sender.send(Message::Packet(Err(err))).await;

                    return;
                }

                Ok(n) => buf.copy_to_bytes(n),
            };

            if let Err(err) = sender.send(Message::Packet(Ok(packet))).await {
                error!(%err, "send packet failed");

                return;
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
                        info!("decode frame done");

                        frame
                    }
                };

                self.encrypt_sender
                    .send(EncryptMessage::Frame(frame))
                    .await
                    .tap_err(|err| error!(%err, "send frame to encrypt failed"))?;

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_channel::mpsc;
    use futures_util::StreamExt;
    use test_log::test;

    use super::*;
    use crate::protocol::FrameType;

    #[test(tokio::test)]
    async fn test() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        let (encrypt_sender, mut encrypt_mailbox) = mpsc::channel(10);
        let (mut mailbox_sender, mailbox) = mpsc::channel(10);
        let mut udp_actor = UdpActor::new(encrypt_sender, mailbox_sender.clone(), mailbox, addr)
            .await
            .unwrap();
        tokio::spawn(async move { udp_actor.run().await });

        let frame = Frame {
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
