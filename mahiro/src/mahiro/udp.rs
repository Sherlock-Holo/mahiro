use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use prost::Message as _;
use ractor::factory::{
    Factory, FactoryMessage, Job, WorkerBuilder, WorkerId, WorkerMessage, WorkerStartContext,
};
use ractor::{Actor, ActorId, ActorProcessingErr, ActorRef};
use tap::TapFallible;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::mahiro::message::EncryptMessage;
use crate::protocol::Frame;

use super::message::UdpMessage as Message;

#[derive(Debug)]
struct UdpActor {
    worker_id: WorkerId,
    remote_addr: SocketAddr,
    encrypt: ActorRef<FactoryMessage<ActorId, EncryptMessage>>,
}

struct UdpActorBuilder {
    remote_addr: SocketAddr,
    encrypt: ActorRef<FactoryMessage<ActorId, EncryptMessage>>,
}

impl WorkerBuilder<UdpActor> for UdpActorBuilder {
    fn build(&self, wid: WorkerId) -> UdpActor {
        UdpActor {
            worker_id: wid,
            remote_addr: self.remote_addr,
            encrypt: self.encrypt.clone(),
        }
    }
}

#[derive(Debug)]
struct State {
    factory: ActorRef<FactoryMessage<ActorId, Message>>,
    udp_socket: Arc<UdpSocket>,
    read_task: JoinHandle<()>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.read_task.abort();
    }
}

#[async_trait]
impl Actor for UdpActor {
    type Msg = WorkerMessage<ActorId, Message>;
    type State = State;
    type Arguments = WorkerStartContext<ActorId, Message>;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .tap_err(|err| error!(%err,"bind udp failed"))?;
        udp_socket.connect(self.remote_addr).await.tap_err(
            |err| error!(%err, remote_addr = %self.remote_addr, "connect remote failed"),
        )?;

        info!(remote_addr = %self.remote_addr, "connect remote done");

        let udp_socket = Arc::new(udp_socket);

        let read_task = {
            let myself = myself.clone();
            let udp_socket = udp_socket.clone();

            tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(4096);
                loop {
                    buf.clear();

                    let packet = match udp_socket.recv_buf(&mut buf).await {
                        Err(err) => {
                            error!(%err, "receive udp socket failed");

                            let _ = myself.send_message(WorkerMessage::Dispatch(Job {
                                key: myself.get_id(),
                                msg: Message::Packet(Err(err)),
                                options: Default::default(),
                            }));

                            return;
                        }

                        Ok(n) => buf.copy_to_bytes(n),
                    };

                    if let Err(err) = myself.send_message(WorkerMessage::Dispatch(Job {
                        key: myself.get_id(),
                        msg: Message::Packet(Ok(packet)),
                        options: Default::default(),
                    })) {
                        error!(%err, "send packet failed");

                        return;
                    }
                }
            })
        };

        Ok(State {
            factory: args.factory,
            udp_socket,
            read_task,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let message = match message {
            WorkerMessage::FactoryPing(ping) => {
                state
                    .factory
                    .send_message(FactoryMessage::WorkerPong(self.worker_id, ping))?;

                return Ok(());
            }
            WorkerMessage::Dispatch(message) => message,
        };

        match message.msg {
            Message::Frame(frame) => {
                let frame_data = frame.encode_to_vec();

                state
                    .udp_socket
                    .send(&frame_data)
                    .await
                    .tap_err(|err| error!(%err, "send frame data failed"))?;

                state.factory.send_message(FactoryMessage::Finished(
                    self.worker_id,
                    state.factory.get_id(),
                ))?;

                Ok(())
            }
            Message::Packet(Err(err)) => Err(err.into()),

            Message::Packet(Ok(packet)) => {
                let frame = match Frame::decode(packet) {
                    Err(err) => {
                        error!(%err, "decode packet failed");

                        state.factory.send_message(FactoryMessage::Finished(
                            self.worker_id,
                            state.factory.get_id(),
                        ))?;

                        return Ok(());
                    }

                    Ok(frame) => {
                        info!("decode frame done");

                        frame
                    }
                };

                self.encrypt
                    .send_message(FactoryMessage::Dispatch(Job {
                        key: self.encrypt.get_id(),
                        msg: EncryptMessage::Frame(frame),
                        options: Default::default(),
                    }))
                    .tap_err(|err| error!(%err, "send frame to encrypt failed"))?;

                Ok(())
            }
        }
    }
}

pub async fn start_udp_actor(
    remote_addr: SocketAddr,
    encrypt: ActorRef<FactoryMessage<ActorId, EncryptMessage>>,
) -> anyhow::Result<(ActorRef<FactoryMessage<ActorId, Message>>, JoinHandle<()>)> {
    let builder = UdpActorBuilder {
        remote_addr,
        encrypt,
    };

    let (udp_actor, task) = Actor::spawn(None, Factory::default(), Box::new(builder)).await?;

    Ok((udp_actor, task))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_channel::mpsc;
    use futures_channel::mpsc::Sender;
    use futures_util::{SinkExt, StreamExt};
    use test_log::test;

    use crate::protocol::FrameType;

    use super::*;

    #[test(tokio::test)]
    async fn test() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        struct StubEncrypt(Sender<Frame>);

        #[async_trait]
        impl Actor for StubEncrypt {
            type Msg = FactoryMessage<ActorId, EncryptMessage>;
            type State = ();
            type Arguments = ();

            async fn pre_start(
                &self,
                _myself: ActorRef<Self::Msg>,
                _args: Self::Arguments,
            ) -> Result<Self::State, ActorProcessingErr> {
                Ok(())
            }

            async fn handle(
                &self,
                _myself: ActorRef<Self::Msg>,
                message: Self::Msg,
                _state: &mut Self::State,
            ) -> Result<(), ActorProcessingErr> {
                let message = match message {
                    FactoryMessage::Dispatch(message) => message,
                    _ => panic!("other factory message"),
                };

                match message.msg {
                    EncryptMessage::Frame(frame) => {
                        self.0.clone().send(frame).await.unwrap();
                    }

                    _ => panic!("other encrypt message"),
                }

                Ok(())
            }
        }

        let (sender, mut receiver) = mpsc::channel(1);
        let (encrypt, _) = Actor::spawn(None, StubEncrypt(sender), ()).await.unwrap();
        let (udp_actor, _) = start_udp_actor(addr, encrypt).await.unwrap();
        let frame = Frame {
            r#type: FrameType::Handshake as _,
            nonce: 0,
            data: Bytes::from_static(b"hello"),
        };

        udp_actor
            .send_message(FactoryMessage::Dispatch(Job {
                key: udp_actor.get_id(),
                msg: Message::Frame(frame.clone()),
                options: Default::default(),
            }))
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

        let receive_frame = receiver.next().await.unwrap();

        assert_eq!(frame, receive_frame);
    }
}
