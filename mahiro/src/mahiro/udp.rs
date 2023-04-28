use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use prost::Message as _;
use ractor::factory::{
    FactoryMessage, Job, WorkerBuilder, WorkerId, WorkerMessage, WorkerStartContext,
};
use ractor::{Actor, ActorId, ActorProcessingErr, ActorRef};
use tap::TapFallible;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::protocol::Frame;

#[derive(Debug)]
struct UdpActor {
    worker_id: WorkerId,
    remote_addr: SocketAddr,
    encrypt: ActorRef<FactoryMessage<ActorId, Frame>>,
}

struct UdpActorBuilder {
    remote_addr: SocketAddr,
    encrypt: ActorRef<FactoryMessage<ActorId, Frame>>,
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

enum Message {
    Frame(Frame),
    Packet(io::Result<Bytes>),
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
                        msg: frame,
                        options: Default::default(),
                    }))
                    .tap_err(|err| error!(%err, "send frame to encrypt failed"))?;

                Ok(())
            }
        }
    }
}
