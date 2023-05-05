use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashSet;
use derivative::Derivative;
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tap::TapFallible;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, error, info, warn};

use crate::encrypt::{Encrypt, HandshakeState};
use crate::protocol::frame_data::DataOrHeartbeat;
use crate::protocol::{Frame, FrameData, FrameType};
use crate::{util, HEARTBEAT_DATA};

use super::message::EncryptMessage as Message;
use super::message::{TunMessage, UdpMessage};
use super::public_key::PublicKey;

#[derive(Derivative)]
#[derivative(Debug)]
enum State {
    Transport {
        encrypt: Encrypt,
        #[derivative(Debug = "ignore")]
        buffer: Vec<u8>,
        heartbeat_receive_instant: Instant,
        heartbeat_task: JoinHandle<()>,
        remote_addr: SocketAddr,
    },
}

impl Drop for State {
    fn drop(&mut self) {
        let Self::Transport { heartbeat_task, .. } = self;
        heartbeat_task.abort();
    }
}

#[derive(Debug)]
pub struct EncryptActor {
    mailbox_sender: Sender<Message>,
    mailbox: Receiver<Message>,
    udp_sender: Sender<UdpMessage>,
    tun_sender: Sender<TunMessage>,
    timeout_notify: Notify,

    state: State,
    heartbeat_interval: Duration,
}

impl EncryptActor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        udp_sender: Sender<UdpMessage>,
        tun_sender: Sender<TunMessage>,
        timeout_notify: Notify,
        local_private_key: Bytes,
        frame: Frame,
        from: SocketAddr,
        heartbeat_interval: Duration,
        remote_public_keys: &DashSet<PublicKey>,
    ) -> anyhow::Result<Self> {
        match frame.r#type() {
            FrameType::Transport => {
                error!("unexpected transport frame");

                Err(anyhow::anyhow!("unexpected transport frame"))
            }
            FrameType::Handshake => {
                let mut encrypt = Encrypt::new_responder(&local_private_key)
                    .tap_err(|err| error!(%err, "create responder encrypt failed"))?;

                match encrypt.responder_handshake(&frame.data) {
                    HandshakeState::Failed(err) => {
                        error!(%err, "responder handshake failed");

                        Err(err.into())
                    }
                    HandshakeState::MissPeerPublicKey => {
                        error!("miss peer public key");

                        Err(anyhow::anyhow!("miss peer public key"))
                    }
                    HandshakeState::PeerPublicKey(public_key) => {
                        if !remote_public_keys.contains(public_key) {
                            error!("unknown public key");

                            return Err(anyhow::anyhow!("unknown public key"));
                        }

                        let response = encrypt.responder_handshake_response()?;
                        let handshake_response_frame = Frame {
                            r#type: FrameType::Handshake as _,
                            nonce: 0,
                            data: Bytes::copy_from_slice(response),
                        };

                        encrypt = encrypt.into_transport_mode()?;

                        {
                            let mut udp_sender = udp_sender.clone();
                            tokio::spawn(async move {
                                udp_sender
                                    .send(UdpMessage::Frame {
                                        frame: handshake_response_frame,
                                        to: from,
                                    })
                                    .await
                                    .tap_err(|err| error!(%err, "send handshake response failed"))
                            });
                        }

                        let heartbeat_task = {
                            let mailbox_sender = mailbox_sender.clone();
                            tokio::spawn(Self::heartbeat(heartbeat_interval, mailbox_sender))
                        };

                        Ok(Self {
                            mailbox_sender,
                            mailbox,
                            udp_sender,
                            tun_sender,
                            timeout_notify,
                            state: State::Transport {
                                encrypt,
                                buffer: vec![0; 65535],
                                heartbeat_receive_instant: Instant::now(),
                                heartbeat_task,
                                remote_addr: from,
                            },
                            heartbeat_interval,
                        })
                    }
                }
            }
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.run_circle().await?;
        }
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

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        let message = match self.mailbox.next().await {
            None => {
                error!("get message from encrypt mailbox failed");

                return Err(anyhow::anyhow!("get message from encrypt mailbox failed"));
            }

            Some(message) => message,
        };

        match &mut self.state {
            State::Transport {
                encrypt,
                buffer,
                heartbeat_receive_instant,
                remote_addr,
                ..
            } => {
                match message {
                    Message::HandshakeTimeout => {
                        // drop or handshake timeout message when actor is transport
                        debug!("ignore handshake message");

                        Ok(())
                    }

                    Message::Packet(packet) => {
                        Self::handle_transport_packet(
                            packet,
                            *remote_addr,
                            buffer,
                            encrypt,
                            &mut self.udp_sender,
                        )
                        .await?;

                        info!("handle transport packet done");

                        Ok(())
                    }

                    Message::Frame { frame, from } => {
                        Self::handle_handshake_frame(
                            frame,
                            from,
                            buffer,
                            encrypt,
                            heartbeat_receive_instant,
                            &mut self.udp_sender,
                            &mut self.tun_sender,
                        )
                        .await?;

                        info!("handle transport frame done");

                        Ok(())
                    }

                    Message::Heartbeat => {
                        Self::handle_transport_heartbeat(
                            buffer,
                            *remote_addr,
                            encrypt,
                            self.heartbeat_interval,
                            heartbeat_receive_instant,
                            &mut self.udp_sender,
                            &self.timeout_notify,
                        )
                        .await?;

                        info!("handle transport heartbeat done");

                        Ok(())
                    }
                }
            }
        }
    }

    async fn handle_transport_packet(
        packet: Bytes,
        to: SocketAddr,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        udp_sender: &mut Sender<UdpMessage>,
    ) -> anyhow::Result<()> {
        let nonce = util::generate_nonce();
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

        udp_sender
            .send(UdpMessage::Frame { frame, to })
            .await
            .tap_err(|err| error!(%err, "send frame failed"))?;

        Ok(())
    }

    async fn handle_handshake_frame(
        frame: Frame,
        from: SocketAddr,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        heartbeat_receive_instant: &mut Instant,
        udp_sender: &mut Sender<UdpMessage>,
        tun_sender: &mut Sender<TunMessage>,
    ) -> anyhow::Result<()> {
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

                            let nonce = util::generate_nonce();
                            let n = encrypt.encrypt(nonce, &pong_frame_data, buffer)?;
                            let pong_data = Bytes::copy_from_slice(&buffer[..n]);
                            let frame = Frame {
                                r#type: FrameType::Transport as _,
                                nonce,
                                data: pong_data,
                            };

                            udp_sender
                                .send(UdpMessage::Frame { frame, to: from })
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
        buffer: &mut [u8],
        to: SocketAddr,
        encrypt: &Encrypt,
        heartbeat_interval: Duration,
        heartbeat_receive_instant: &mut Instant,
        udp_sender: &mut Sender<UdpMessage>,
        timeout_notify: &Notify,
    ) -> anyhow::Result<()> {
        if heartbeat_receive_instant.elapsed() > heartbeat_interval * 2 {
            error!("heartbeat timeout");

            timeout_notify.notify_one();

            return Err(anyhow::anyhow!("heartbeat timeout"));
        }

        let ping_frame_data = FrameData {
            data_or_heartbeat: Some(DataOrHeartbeat::Ping(Bytes::from_static(HEARTBEAT_DATA))),
        }
        .encode_to_vec();
        let nonce = util::generate_nonce();

        let n = encrypt.encrypt(nonce, &ping_frame_data, buffer)?;

        let frame = Frame {
            r#type: FrameType::Transport as _,
            nonce,
            data: Bytes::copy_from_slice(&buffer[..n]),
        };

        udp_sender
            .send(UdpMessage::Frame { frame, to })
            .await
            .tap_err(|err| error!(%err, "send udp heartbeat frame failed"))?;

        Ok(())
    }
}
