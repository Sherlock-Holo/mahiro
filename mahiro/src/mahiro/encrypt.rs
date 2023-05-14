use std::time::{Duration, Instant};

use bytes::Bytes;
use derivative::Derivative;
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tap::TapFallible;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, error, info, instrument, warn};

use super::message::EncryptMessage as Message;
use crate::cookie::generate_cookie;
use crate::encrypt::Encrypt;
use crate::mahiro::message::{TunMessage, UdpMessage};
use crate::protocol::frame_data::DataOrHeartbeat;
use crate::protocol::{Frame, FrameData, FrameType};
use crate::public_key::PublicKey;
use crate::timestamp::generate_timestamp;
use crate::{util, HEARTBEAT_DATA};

#[derive(Derivative)]
#[derivative(Debug)]
enum State {
    Uninit {
        encrypt: Option<Encrypt>,
    },

    Handshake {
        cookie: Bytes,
        encrypt: Option<Encrypt>,
    },

    Transport {
        cookie: Bytes,
        encrypt: Encrypt,
        #[derivative(Debug = "ignore")]
        buffer: Vec<u8>,
        heartbeat_receive_instant: Instant,
        heartbeat_task: JoinHandle<()>,
    },
}

impl Drop for State {
    fn drop(&mut self) {
        if let Self::Transport { heartbeat_task, .. } = self {
            heartbeat_task.abort();
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct EncryptActor {
    mailbox_sender: Sender<Message>,
    mailbox: Receiver<Message>,
    udp_sender: Sender<UdpMessage>,
    tun_sender: Sender<TunMessage>,

    state: State,
    heartbeat_interval: Duration,

    #[derivative(Debug = "ignore")]
    local_private_key: Bytes,
    peer_public_key: PublicKey,
}

impl EncryptActor {
    pub async fn new(
        udp_sender: Sender<UdpMessage>,
        tun_sender: Sender<TunMessage>,
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        heartbeat_interval: Duration,
        local_private_key: Bytes,
        peer_public_key: PublicKey,
    ) -> anyhow::Result<Self> {
        let state =
            Self::start(&local_private_key, &peer_public_key, mailbox_sender.clone()).await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            udp_sender,
            tun_sender,
            state,
            heartbeat_interval,
            local_private_key,
            peer_public_key,
        })
    }

    async fn start(
        local_private_key: &[u8],
        peer_public_key: &[u8],
        mut mailbox_sender: Sender<Message>,
    ) -> anyhow::Result<State> {
        let encrypt = Encrypt::new_initiator(local_private_key, peer_public_key)
            .tap_err(|err| error!(%err, "create initiator encrypt failed"))?;
        let state = State::Uninit {
            encrypt: Some(encrypt),
        };

        mailbox_sender
            .send(Message::Init)
            .await
            .tap_err(|err| error!(%err, "send init message failed"))?;

        Ok(state)
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        let state = Self::start(
            &self.local_private_key,
            &self.peer_public_key,
            self.mailbox_sender.clone(),
        )
        .await?;
        self.state = state;

        Ok(())
    }

    async fn heartbeat(heartbeat_interval: Duration, mut mailbox_sender: Sender<Message>) {
        let mut interval_stream = IntervalStream::new(time::interval(heartbeat_interval));
        interval_stream
            .next()
            .await
            .expect("unexpect interval stream stopped");

        while interval_stream.next().await.is_some() {
            if let Err(err) = mailbox_sender.send(Message::Heartbeat).await {
                error!(%err, "send heartbeat message failed");
            }
        }
    }

    pub async fn run(&mut self) {
        loop {
            if let Err(err) = self.run_circle().await {
                error!(%err, "encrypt actor run circle failed, need restart");

                loop {
                    match self.restart().await {
                        Err(err) => {
                            error!(%err, "encrypt actor restart failed");
                        }

                        Ok(_) => {
                            info!("encrypt actor restart done");

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
                error!("get message from encrypt mailbox failed");

                return Err(anyhow::anyhow!("get message from encrypt mailbox failed"));
            }

            Some(message) => message,
        };

        match &mut self.state {
            State::Uninit { encrypt } => {
                if let Some(new_state) = Self::handle_uninit(
                    encrypt.take().unwrap(),
                    self.heartbeat_interval,
                    &self.mailbox_sender,
                    &mut self.udp_sender,
                )
                .await?
                {
                    self.state = new_state;

                    info!("change to handshake state done");
                }

                Ok(())
            }

            State::Handshake { cookie, encrypt } => {
                if let Some(new_state) = Self::handle_handshake(
                    message,
                    cookie,
                    encrypt,
                    self.heartbeat_interval,
                    self.mailbox_sender.clone(),
                )
                .await?
                {
                    self.state = new_state;

                    info!("handshake done");
                }

                Ok(())
            }

            State::Transport {
                cookie,
                encrypt,
                buffer,
                heartbeat_receive_instant,
                ..
            } => {
                match message {
                    Message::Init | Message::HandshakeTimeout => {
                        // drop init or handshake timeout message when actor is transport
                        debug!("ignore init or handshake message");

                        Ok(())
                    }

                    Message::Packet(packet) => {
                        Self::handle_transport_packet(
                            cookie,
                            packet,
                            buffer,
                            encrypt,
                            &mut self.udp_sender,
                        )
                        .await?;

                        debug!("handle transport packet done");

                        Ok(())
                    }

                    Message::Frame(frame) => {
                        Self::handle_transport_frame(
                            cookie,
                            frame,
                            buffer,
                            encrypt,
                            heartbeat_receive_instant,
                            &mut self.udp_sender,
                            &mut self.tun_sender,
                        )
                        .await?;

                        debug!("handle transport frame done");

                        Ok(())
                    }

                    Message::Heartbeat => {
                        Self::handle_transport_heartbeat(
                            cookie,
                            buffer,
                            encrypt,
                            self.heartbeat_interval,
                            heartbeat_receive_instant,
                            &mut self.udp_sender,
                        )
                        .await?;

                        debug!("handle transport heartbeat done");

                        Ok(())
                    }
                }
            }
        }
    }

    async fn handle_uninit(
        mut encrypt: Encrypt,
        handshake_timeout: Duration,
        mailbox_sender: &Sender<Message>,
        udp_sender: &mut Sender<UdpMessage>,
    ) -> anyhow::Result<Option<State>> {
        let cookie = generate_cookie();
        let timestamp = generate_timestamp();
        let timestamp = timestamp.to_be_bytes();
        let handshake = Bytes::from(encrypt.initiator_handshake(&timestamp)?.to_vec());

        let frame = Frame {
            cookie: cookie.clone(),
            r#type: FrameType::Handshake as _,
            nonce: 0,
            data: handshake,
        };

        udp_sender
            .send(UdpMessage::Frame(frame))
            .await
            .tap_err(|err| error!(%err, "send handshake frame failed"))?;

        let mut mailbox_sender = mailbox_sender.clone();
        tokio::spawn(async move {
            time::sleep(handshake_timeout).await;

            let _ = mailbox_sender.send(Message::HandshakeTimeout).await;
        });

        Ok(Some(State::Handshake {
            cookie,
            encrypt: Some(encrypt),
        }))
    }

    async fn handle_handshake(
        message: Message,
        cookie: &Bytes,
        encrypt: &mut Option<Encrypt>,
        heartbeat_interval: Duration,
        mailbox_sender: Sender<Message>,
    ) -> anyhow::Result<Option<State>> {
        let data = match message {
            Message::Init | Message::Packet(_) | Message::Heartbeat => {
                // drop init, packet or heartbeat when actor is handshaking

                return Ok(None);
            }
            Message::HandshakeTimeout => {
                error!("handshake timeout");

                return Err(anyhow::anyhow!("handshake timeout"));
            }

            Message::Frame(frame) => {
                if frame.r#type() != FrameType::Handshake {
                    error!("invalid frame type");

                    return Ok(None);
                }

                frame.data
            }
        };

        encrypt
            .as_mut()
            .unwrap()
            .initiator_handshake_response(&data)?;

        let mut encrypt = encrypt.take().unwrap();
        encrypt = encrypt.into_transport_mode()?;

        let heartbeat_task =
            tokio::spawn(async move { Self::heartbeat(heartbeat_interval, mailbox_sender).await });

        Ok(Some(State::Transport {
            cookie: cookie.clone(),
            encrypt,
            buffer: vec![0; 65535],
            heartbeat_receive_instant: Instant::now(),
            heartbeat_task,
        }))
    }

    async fn handle_transport_packet(
        cookie: &Bytes,
        packet: Bytes,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        udp_sender: &mut Sender<UdpMessage>,
    ) -> anyhow::Result<()> {
        let nonce = util::generate_nonce();
        let data = FrameData {
            timestamp: generate_timestamp(),
            data_or_heartbeat: Some(DataOrHeartbeat::Data(packet)),
        }
        .encode_to_vec();
        let n = encrypt.encrypt(nonce, &data, buffer)?;
        let data = Bytes::copy_from_slice(&buffer[..n]);

        let frame = Frame {
            cookie: cookie.clone(),
            r#type: FrameType::Transport as _,
            nonce,
            data,
        };

        udp_sender
            .send(UdpMessage::Frame(frame))
            .await
            .tap_err(|err| error!(%err, "send frame failed"))?;

        Ok(())
    }

    async fn handle_transport_frame(
        cookie: &Bytes,
        frame: Frame,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        heartbeat_receive_instant: &mut Instant,
        udp_sender: &mut Sender<UdpMessage>,
        tun_sender: &mut Sender<TunMessage>,
    ) -> anyhow::Result<()> {
        if frame.cookie != cookie {
            error!("drop invalid cookie frame");

            return Ok(());
        }

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
                                timestamp: generate_timestamp(),
                                data_or_heartbeat: Some(DataOrHeartbeat::Pong(Bytes::from_static(
                                    HEARTBEAT_DATA,
                                ))),
                            }
                            .encode_to_vec();

                            let nonce = util::generate_nonce();
                            let n = encrypt.encrypt(nonce, &pong_frame_data, buffer)?;
                            let pong_data = Bytes::copy_from_slice(&buffer[..n]);
                            let frame = Frame {
                                cookie: cookie.clone(),
                                r#type: FrameType::Transport as _,
                                nonce,
                                data: pong_data,
                            };

                            udp_sender
                                .send(UdpMessage::Frame(frame))
                                .await
                                .tap_err(|err| error!(%err, "send pong frame failed"))?;
                        }

                        Ok(())
                    }

                    Some(DataOrHeartbeat::Data(data)) => {
                        tun_sender
                            .send(TunMessage::ToTun(data.clone()))
                            .await
                            .tap_err(|err| error!(%err, "send packet failed"))?;

                        Ok(())
                    }
                }
            }
        }
    }

    async fn handle_transport_heartbeat(
        cookie: &Bytes,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        heartbeat_interval: Duration,
        heartbeat_receive_instant: &mut Instant,
        udp_sender: &mut Sender<UdpMessage>,
    ) -> anyhow::Result<()> {
        if heartbeat_receive_instant.elapsed() > heartbeat_interval * 2 {
            error!("heartbeat timeout");

            return Err(anyhow::anyhow!("heartbeat timeout"));
        }

        let ping_frame_data = FrameData {
            timestamp: generate_timestamp(),
            data_or_heartbeat: Some(DataOrHeartbeat::Ping(Bytes::from_static(HEARTBEAT_DATA))),
        }
        .encode_to_vec();
        let nonce = util::generate_nonce();

        let n = encrypt.encrypt(nonce, &ping_frame_data, buffer)?;

        let frame = Frame {
            cookie: cookie.clone(),
            r#type: FrameType::Transport as _,
            nonce,
            data: Bytes::copy_from_slice(&buffer[..n]),
        };

        udp_sender
            .send(UdpMessage::Frame(frame))
            .await
            .tap_err(|err| error!(%err, "send udp heartbeat frame failed"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures_channel::mpsc;
    use snow::params::NoiseParams;
    use snow::{Builder, StatelessTransportState};
    use test_log::test;

    use super::*;

    #[test(tokio::test)]
    async fn test() {
        let noise_params = NoiseParams::from_str("Noise_IK_25519_ChaChaPoly_BLAKE2s").unwrap();
        let builder = Builder::new(noise_params);
        let initiator_keypair = builder.generate_keypair().unwrap();
        let responder_keypair = builder.generate_keypair().unwrap();
        let mut handshake_state = builder
            .local_private_key(&responder_keypair.private)
            .build_responder()
            .unwrap();
        let mut buf = vec![0; 65535];

        let (tun_sender, mut tun_mailbox) = mpsc::channel(10);
        let (udp_sender, mut udp_mailbox) = mpsc::channel(10);
        let (mut mailbox_sender, mailbox) = mpsc::channel(10);

        let mut encrypt_actor = EncryptActor::new(
            udp_sender,
            tun_sender.clone(),
            mailbox_sender.clone(),
            mailbox,
            Duration::from_secs(10),
            initiator_keypair.private.into(),
            responder_keypair.public.into(),
        )
        .await
        .unwrap();

        tokio::spawn(async move { encrypt_actor.run().await });

        // ---- handshake ----

        let udp_message = udp_mailbox.next().await.unwrap();
        let frame = match udp_message {
            UdpMessage::Frame(frame) => frame,
            UdpMessage::Packet(_) => {
                panic!("other udp message");
            }
        };

        assert_eq!(frame.r#type(), FrameType::Handshake);

        handshake_state.read_message(&frame.data, &mut buf).unwrap();
        assert_eq!(
            handshake_state.get_remote_static().unwrap(),
            initiator_keypair.public
        );

        let cookie = frame.cookie;
        let timestamp = generate_timestamp().to_be_bytes();
        let n = handshake_state.write_message(&timestamp, &mut buf).unwrap();
        let frame = Frame {
            cookie: cookie.clone(),
            r#type: FrameType::Handshake as _,
            nonce: 0,
            data: Bytes::copy_from_slice(&buf[..n]),
        };
        mailbox_sender.send(Message::Frame(frame)).await.unwrap();

        let transport_state = handshake_state.into_stateless_transport_mode().unwrap();

        // make sure encrypt actor finish become transport
        time::sleep(Duration::from_millis(100)).await;

        // ---- encrypt send to udp ----

        mailbox_sender
            .send(Message::Packet(Bytes::from_static(b"hello")))
            .await
            .unwrap();

        let mut data = receive_data_frame(&mut udp_mailbox, &transport_state, &mut buf).await;
        assert_eq!(data.as_ref(), b"hello");

        mailbox_sender
            .send(Message::Packet(Bytes::from_static(b"mahiro")))
            .await
            .unwrap();

        data = receive_data_frame(&mut udp_mailbox, &transport_state, &mut buf).await;
        assert_eq!(data.as_ref(), b"mahiro");

        // ---- udp send to encrypt ----

        let frame_data = FrameData {
            timestamp: generate_timestamp(),
            data_or_heartbeat: Some(DataOrHeartbeat::Data(Bytes::from_static(b"mihari"))),
        }
        .encode_to_vec();
        let nonce = util::generate_nonce();
        let n = transport_state
            .write_message(nonce, &frame_data, &mut buf)
            .unwrap();
        let frame = Frame {
            cookie,
            r#type: FrameType::Transport as _,
            nonce,
            data: Bytes::copy_from_slice(&buf[..n]),
        };

        mailbox_sender.send(Message::Frame(frame)).await.unwrap();

        let tun_message = tun_mailbox.next().await.unwrap();
        let data = match tun_message {
            TunMessage::FromTun(_) => {
                panic!("other tun message");
            }
            TunMessage::ToTun(data) => data,
        };

        assert_eq!(data.as_ref(), b"mihari");
    }

    async fn receive_data_frame(
        udp_mailbox: &mut Receiver<UdpMessage>,
        transport_state: &StatelessTransportState,
        buf: &mut [u8],
    ) -> Bytes {
        loop {
            let udp_message = udp_mailbox.next().await.unwrap();
            let frame = match udp_message {
                UdpMessage::Frame(frame) => frame,
                UdpMessage::Packet(_) => {
                    panic!("other udp message");
                }
            };

            assert_eq!(frame.r#type(), FrameType::Transport);

            info!("receive frame");

            let n = transport_state
                .read_message(frame.nonce, &frame.data, buf)
                .unwrap();
            let frame_data = FrameData::decode(&buf[..n]).unwrap();
            let data = match frame_data.data_or_heartbeat {
                Some(DataOrHeartbeat::Data(data)) => data,
                Some(DataOrHeartbeat::Ping(_)) => {
                    info!("ignore ping");

                    continue;
                }
                _ => panic!("other frame data {:?}", frame_data.data_or_heartbeat),
            };

            return data;
        }
    }
}
