use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use prost::Message as _;
use ractor::concurrency::JoinHandle;
use ractor::factory::{
    FactoryMessage, Job, WorkerBuilder, WorkerId, WorkerMessage, WorkerStartContext,
};
use ractor::{Actor, ActorId, ActorProcessingErr, ActorRef, MessagingErr};
use rand::{thread_rng, Rng};
use tap::TapFallible;
use tracing::{error, warn};

use crate::encrypt::{Encrypt, HandshakeState};
use crate::protocol::frame_data::DataOrHeartbeat;
use crate::protocol::{Frame, FrameData, FrameType};
use crate::HEARTBEAT_DATA;

use super::message::EncryptMessage as Message;

enum State {
    Uninit {
        factory: ActorRef<FactoryMessage<ActorId, Message>>,
    },
    Handshake {
        factory: ActorRef<FactoryMessage<ActorId, Message>>,
        encrypt: Option<Encrypt>,
    },
    Transport {
        factory: ActorRef<FactoryMessage<ActorId, Message>>,
        encrypt: Option<Encrypt>,
        buffer: Vec<u8>,
        heartbeat_task: JoinHandle<()>,
        heartbeat_receive_instant: Instant,
    },
}

impl State {
    fn factory(&self) -> &ActorRef<FactoryMessage<ActorId, Message>> {
        match self {
            State::Uninit { factory } => factory,
            State::Handshake { factory, .. } => factory,
            State::Transport { factory, .. } => factory,
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        // stop the heartbeat task
        if let State::Transport { heartbeat_task, .. } = self {
            heartbeat_task.abort();
        }
    }
}

struct EncryptActor {
    worker_id: WorkerId,
    local_private_key: Bytes,
    remote_public_key: Bytes,
    tun: ActorRef<FactoryMessage<ActorId, Bytes>>,
    udp: ActorRef<FactoryMessage<ActorId, Frame>>,
    heartbeat_interval: Duration,
}

struct EncryptActorBuilder {
    local_private_key: Bytes,
    remote_public_key: Bytes,
    tun: ActorRef<FactoryMessage<ActorId, Bytes>>,
    udp: ActorRef<FactoryMessage<ActorId, Frame>>,
    heartbeat_interval: Duration,
}

impl WorkerBuilder<EncryptActor> for EncryptActorBuilder {
    fn build(&self, wid: WorkerId) -> EncryptActor {
        EncryptActor {
            worker_id: wid,
            local_private_key: self.local_private_key.clone(),
            remote_public_key: self.remote_public_key.clone(),
            tun: self.tun.clone(),
            udp: self.udp.clone(),
            heartbeat_interval: self.heartbeat_interval,
        }
    }
}

#[async_trait]
impl Actor for EncryptActor {
    type Msg = WorkerMessage<ActorId, Message>;
    type State = State;
    type Arguments = WorkerStartContext<ActorId, Message>;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let id = myself.get_id();

        myself.send_message(WorkerMessage::Dispatch(Job {
            key: id,
            msg: Message::Init,
            options: Default::default(),
        }))?;

        Ok(State::Uninit {
            factory: args.factory,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let message = match message {
            WorkerMessage::FactoryPing(ping) => {
                state
                    .factory()
                    .send_message(FactoryMessage::WorkerPong(self.worker_id, ping))?;

                return Ok(());
            }
            WorkerMessage::Dispatch(message) => message,
        };

        match state {
            State::Uninit { factory } => {
                let factory = factory.clone();
                if let Some(new_state) = self.handle_uninit(&factory).await? {
                    *state = new_state;
                }

                factory.send_message(FactoryMessage::Finished(self.worker_id, message.key))?;

                Ok(())
            }

            State::Handshake { factory, encrypt } => {
                let factory = factory.clone();
                let id = message.key;
                if let Some(new_state) = self
                    .handle_handshake(myself, message, &factory, encrypt)
                    .await?
                {
                    *state = new_state;
                }

                factory.send_message(FactoryMessage::Finished(self.worker_id, id))?;

                Ok(())
            }

            State::Transport {
                factory,
                encrypt,
                buffer,
                heartbeat_receive_instant,
                ..
            } => {
                let encrypt = encrypt.as_mut().unwrap();

                match message.msg {
                    Message::Init | Message::HandshakeTimeout => {
                        // drop init or handshake timeout message when actor is transport
                        factory
                            .send_message(FactoryMessage::Finished(self.worker_id, message.key))?;

                        Ok(())
                    }

                    Message::Packet(packet) => {
                        self.handle_transport_packet(packet, buffer, encrypt)
                            .await?;

                        factory
                            .send_message(FactoryMessage::Finished(self.worker_id, message.key))?;

                        Ok(())
                    }

                    Message::Frame(frame) => {
                        self.handle_transport_frame(
                            frame,
                            buffer,
                            encrypt,
                            heartbeat_receive_instant,
                        )
                        .await?;

                        factory
                            .send_message(FactoryMessage::Finished(self.worker_id, message.key))?;

                        Ok(())
                    }

                    Message::Heartbeat => {
                        self.handle_transport_heartbeat(buffer, encrypt, heartbeat_receive_instant)
                            .await?;

                        Ok(())
                    }
                }
            }
        }
    }
}

impl EncryptActor {
    fn send_udp(&self, frame: Frame) -> Result<(), MessagingErr> {
        let id = self.udp.get_id();
        self.udp.send_message(FactoryMessage::Dispatch(Job {
            key: id,
            msg: frame,
            options: Default::default(),
        }))
    }

    fn send_tun(&self, packet: Bytes) -> Result<(), MessagingErr> {
        let id = self.tun.get_id();
        self.tun.send_message(FactoryMessage::Dispatch(Job {
            key: id,
            msg: packet,
            options: Default::default(),
        }))
    }

    async fn handle_uninit(
        &self,
        factory: &ActorRef<FactoryMessage<ActorId, Message>>,
    ) -> Result<Option<State>, ActorProcessingErr> {
        let mut encrypt = Encrypt::new_initiator(&self.local_private_key)
            .tap_err(|err| error!(%err, "create initiator failed"))?;
        let handshake = Bytes::from(encrypt.initiator_handshake()?.to_vec());

        let handshake_data = FrameData {
            data_or_heartbeat: Some(DataOrHeartbeat::Data(handshake)),
        }
        .encode_to_vec();

        let frame = Frame {
            r#type: FrameType::Handshake as _,
            nonce: 0,
            data: handshake_data.into(),
        };
        self.send_udp(frame)
            .tap_err(|err| error!(%err, "send handshake frame failed"))?;

        Ok(Some(State::Handshake {
            factory: factory.clone(),
            encrypt: Some(encrypt),
        }))
    }

    async fn handle_handshake(
        &self,
        myself: ActorRef<WorkerMessage<ActorId, Message>>,
        message: Job<ActorId, Message>,
        factory: &ActorRef<FactoryMessage<ActorId, Message>>,
        encrypt: &mut Option<Encrypt>,
    ) -> Result<Option<State>, ActorProcessingErr> {
        let data = match message.msg {
            Message::Init | Message::Packet(_) | Message::Heartbeat => {
                // drop init, packet or heartbeat when actor is handshaking

                return Ok(None);
            }
            Message::HandshakeTimeout => {
                error!("handshake timeout");

                return Err("handshake timeout".into());
            }

            Message::Frame(frame) => {
                if frame.r#type() != FrameType::Handshake {
                    error!("invalid frame type");

                    return Ok(None);
                }

                frame.data
            }
        };

        return match encrypt
            .as_mut()
            .unwrap()
            .initiator_handshake_response(&data)
        {
            HandshakeState::Failed(err) => {
                error!(%err, "handshake failed");

                Err(err.into())
            }

            HandshakeState::MissPeerPublicKey => {
                error!("invalid handshake");

                Ok(None)
            }
            HandshakeState::PeerPublicKey(public_key) => {
                if self.remote_public_key != public_key {
                    error!("incorrect public key");

                    return Err("incorrect public key".into());
                }

                let mut encrypt = encrypt.take().unwrap();
                encrypt = encrypt.into_transport_mode()?;

                let factory = factory.clone();

                let id = myself.get_id();
                let task = myself.send_interval(self.heartbeat_interval, move || {
                    WorkerMessage::Dispatch(Job {
                        key: id,
                        msg: Message::Heartbeat,
                        options: Default::default(),
                    })
                });

                Ok(Some(State::Transport {
                    factory,
                    encrypt: Some(encrypt),
                    buffer: vec![0; 65535],
                    heartbeat_task: task,
                    heartbeat_receive_instant: Instant::now(),
                }))
            }
        };
    }

    async fn handle_transport_packet(
        &self,
        packet: Bytes,
        buffer: &mut [u8],
        encrypt: &Encrypt,
    ) -> Result<(), ActorProcessingErr> {
        let nonce = generate_nonce();
        let data = FrameData {
            data_or_heartbeat: Some(DataOrHeartbeat::Data(packet)),
        }
        .encode_to_vec();
        let n = encrypt.encrypt(nonce, &data, buffer)?;
        let data = Bytes::copy_from_slice(&buffer[..n]);

        let frame = Frame {
            r#type: FrameType::Transport as _,
            nonce,
            data,
        };

        self.send_udp(frame)
            .tap_err(|err| error!(%err, "send frame failed"))?;

        Ok(())
    }

    async fn handle_transport_frame(
        &self,
        frame: Frame,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        heartbeat_receive_instant: &mut Instant,
    ) -> Result<(), ActorProcessingErr> {
        match frame.r#type() {
            FrameType::Handshake => {
                warn!("receive handshake when actor is transport");

                Ok(())
            }
            FrameType::Transport => {
                let nonce = frame.nonce;
                let data = frame.data;
                let data = match encrypt.decrypt(nonce, &data, buffer) {
                    Err(err) => {
                        error!(%err, "decrypt frame data failed, drop it");

                        return Ok(());
                    }

                    Ok(n) => &buffer[..n],
                };

                let frame_data = match FrameData::decode(data) {
                    Err(err) => {
                        error!(%err, "decode frame data failed");

                        return Ok(());
                    }

                    Ok(frame_data) => frame_data,
                };

                match &frame_data.data_or_heartbeat {
                    None => {
                        error!("miss frame data");

                        Ok(())
                    }

                    Some(DataOrHeartbeat::Pong(data) | DataOrHeartbeat::Ping(data)) => {
                        if data != HEARTBEAT_DATA {
                            error!("invalid heartbeat data");

                            return Ok(());
                        }

                        if matches!(frame_data.data_or_heartbeat, Some(DataOrHeartbeat::Pong(_))) {
                            *heartbeat_receive_instant = Instant::now();
                        } else {
                            let pong_frame_data = FrameData {
                                data_or_heartbeat: Some(DataOrHeartbeat::Pong(Bytes::from_static(
                                    HEARTBEAT_DATA,
                                ))),
                            }
                            .encode_to_vec();

                            let nonce = generate_nonce();
                            let n = encrypt.encrypt(nonce, &pong_frame_data, buffer)?;
                            let pong_data = Bytes::copy_from_slice(&buffer[..n]);
                            let frame = Frame {
                                r#type: FrameType::Transport as _,
                                nonce,
                                data: pong_data,
                            };

                            self.send_udp(frame)
                                .tap_err(|err| error!(%err, "send pong frame failed"))?;
                        }

                        Ok(())
                    }

                    Some(DataOrHeartbeat::Data(data)) => {
                        let data = match encrypt.decrypt(nonce, data, buffer) {
                            Err(err) => {
                                error!(%err, "decrypt failed, drop it");

                                return Ok(());
                            }

                            Ok(n) => &buffer[..n],
                        };

                        self.send_tun(Bytes::copy_from_slice(data))
                            .tap_err(|err| error!(%err, "send packet failed"))?;

                        Ok(())
                    }
                }
            }
        }
    }

    async fn handle_transport_heartbeat(
        &self,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        heartbeat_receive_instant: &mut Instant,
    ) -> Result<(), ActorProcessingErr> {
        if heartbeat_receive_instant.elapsed() > self.heartbeat_interval * 2 {
            error!("heartbeat timeout");

            return Err("heartbeat timeout".into());
        }

        let ping_frame_data = FrameData {
            data_or_heartbeat: Some(DataOrHeartbeat::Ping(Bytes::from_static(HEARTBEAT_DATA))),
        }
        .encode_to_vec();
        let nonce = generate_nonce();

        let n = encrypt.encrypt(nonce, &ping_frame_data, buffer)?;

        let frame = Frame {
            r#type: FrameType::Transport as _,
            nonce,
            data: Bytes::copy_from_slice(&buffer[..n]),
        };

        self.send_udp(frame)?;

        Ok(())
    }
}

fn generate_nonce() -> u64 {
    thread_rng().gen()
}
