use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashSet;
use derivative::Derivative;
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tap::TapFallible;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, error, instrument, warn};

use super::connected_peer::ConnectedPeers;
use super::message::EncryptMessage as Message;
use super::message::{TunMessage, UdpMessage};
use crate::encrypt::Encrypt;
use crate::ip_packet;
use crate::ip_packet::IpLocation;
use crate::protocol::frame_data::DataOrHeartbeat;
use crate::protocol::{Frame, FrameData, FrameType};
use crate::public_key::PublicKey;
use crate::{util, HEARTBEAT_DATA};

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
        saved_mahiro_ipv4: bool,
        saved_mahiro_ipv6: bool,
        saved_mahiro_link_local_ipv6: bool,
        connected_peers: ConnectedPeers,
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
        local_private_key: Bytes,
        frame: Frame,
        from: SocketAddr,
        heartbeat_interval: Duration,
        remote_public_keys: &DashSet<PublicKey>,
        connected_peers: &ConnectedPeers,
    ) -> anyhow::Result<(Self, Frame)> {
        match frame.r#type() {
            FrameType::Transport => {
                error!("unexpected transport frame");

                Err(anyhow::anyhow!("unexpected transport frame"))
            }
            FrameType::Handshake => {
                let mut encrypt = Encrypt::new_responder(&local_private_key)
                    .tap_err(|err| error!(%err, "create responder encrypt failed"))?;

                let responder_handshake_success = encrypt.responder_handshake(&frame.data)?;
                if !remote_public_keys.contains(responder_handshake_success.peer_public_key) {
                    error!("unknown public key");

                    return Err(anyhow::anyhow!("unknown public key"));
                }

                let response = encrypt.responder_handshake_response(&[])?;
                let handshake_response_frame = Frame {
                    r#type: FrameType::Handshake as _,
                    nonce: 0,
                    data: Bytes::copy_from_slice(response),
                };

                encrypt = encrypt.into_transport_mode()?;

                let heartbeat_task = {
                    let mailbox_sender = mailbox_sender.clone();
                    tokio::spawn(Self::heartbeat(heartbeat_interval, mailbox_sender))
                };

                Ok((
                    Self {
                        mailbox_sender,
                        mailbox,
                        udp_sender,
                        tun_sender,
                        state: State::Transport {
                            encrypt,
                            buffer: vec![0; 65535],
                            heartbeat_receive_instant: Instant::now(),
                            heartbeat_task,
                            remote_addr: from,
                            saved_mahiro_ipv4: false,
                            saved_mahiro_ipv6: false,
                            saved_mahiro_link_local_ipv6: false,
                            connected_peers: connected_peers.clone(),
                        },
                        heartbeat_interval,
                    },
                    handshake_response_frame,
                ))
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
            State::Transport {
                encrypt,
                buffer,
                heartbeat_receive_instant,
                remote_addr,
                saved_mahiro_ipv4,
                saved_mahiro_ipv6,
                saved_mahiro_link_local_ipv6,
                connected_peers,
                ..
            } => match message {
                Message::Packet(packet) => {
                    Self::handle_transport_packet(
                        packet,
                        *remote_addr,
                        buffer,
                        encrypt,
                        &mut self.udp_sender,
                    )
                    .await?;

                    debug!("handle transport packet done");

                    Ok(())
                }

                Message::Frame { frame, from } => {
                    Self::handle_handshake_frame(HandleHandshakeFrameArgs {
                        frame,
                        from,
                        buffer,
                        encrypt,
                        heartbeat_receive_instant,
                        saved_mahiro_ipv4,
                        saved_mahiro_ipv6,
                        saved_mahiro_link_local_ipv6,
                        mailbox_sender: &self.mailbox_sender,
                        udp_sender: &mut self.udp_sender,
                        tun_sender: &mut self.tun_sender,
                        connected_peers,
                    })
                    .await?;

                    debug!("handle transport frame done");

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
                    )
                    .await?;

                    debug!("handle transport heartbeat done");

                    Ok(())
                }
            },
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
        HandleHandshakeFrameArgs {
            frame,
            from,
            buffer,
            encrypt,
            heartbeat_receive_instant,
            saved_mahiro_ipv4,
            saved_mahiro_ipv6,
            saved_mahiro_link_local_ipv6,
            mailbox_sender,
            udp_sender,
            tun_sender,
            connected_peers,
        }: HandleHandshakeFrameArgs<'_>,
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
                        if !*saved_mahiro_ipv4
                            || !*saved_mahiro_ipv6
                            || !*saved_mahiro_link_local_ipv6
                        {
                            let mahiro_ip = match ip_packet::get_packet_ip(data, IpLocation::Src) {
                                None => {
                                    error!("packet has no ip, drop it");

                                    return Ok(());
                                }

                                Some(mahiro_addr) => mahiro_addr,
                            };

                            debug!(%mahiro_ip, "get mahiro ip done");

                            match mahiro_ip {
                                IpAddr::V4(_) => {
                                    if !*saved_mahiro_ipv4 {
                                        connected_peers
                                            .add_mahiro_ip(mahiro_ip, mailbox_sender.clone());

                                        *saved_mahiro_ipv4 = true;
                                    }
                                }
                                IpAddr::V6(ip) => {
                                    if ip.is_unicast_link_local() && !*saved_mahiro_link_local_ipv6
                                    {
                                        connected_peers
                                            .add_mahiro_ip(mahiro_ip, mailbox_sender.clone());

                                        *saved_mahiro_link_local_ipv6 = true;
                                    }

                                    if !ip.is_unicast_link_local() && !*saved_mahiro_ipv6 {
                                        connected_peers
                                            .add_mahiro_ip(mahiro_ip, mailbox_sender.clone());

                                        *saved_mahiro_ipv6 = true;
                                    }
                                }
                            }
                        }

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
    ) -> anyhow::Result<()> {
        if heartbeat_receive_instant.elapsed() > heartbeat_interval * 2 {
            error!("heartbeat timeout");

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

struct HandleHandshakeFrameArgs<'a> {
    frame: Frame,
    from: SocketAddr,
    buffer: &'a mut [u8],
    encrypt: &'a Encrypt,
    heartbeat_receive_instant: &'a mut Instant,
    saved_mahiro_ipv4: &'a mut bool,
    saved_mahiro_ipv6: &'a mut bool,
    saved_mahiro_link_local_ipv6: &'a mut bool,
    mailbox_sender: &'a Sender<Message>,
    udp_sender: &'a mut Sender<UdpMessage>,
    tun_sender: &'a mut Sender<TunMessage>,
    connected_peers: &'a ConnectedPeers,
}

#[cfg(test)]
mod tests {
    use futures_channel::mpsc;
    use test_log::test;

    use super::*;

    #[test(tokio::test)]
    async fn test() {
        let initiator_keypair = Encrypt::generate_keypair().unwrap();
        let responder_keypair = Encrypt::generate_keypair().unwrap();
        let mut initiator_encrypt =
            Encrypt::new_initiator(&initiator_keypair.private, &responder_keypair.public).unwrap();
        let (tun_sender, mut tun_mailbox) = mpsc::channel(10);
        let (udp_sender, mut udp_mailbox) = mpsc::channel(10);
        let (mut mailbox_sender, mailbox) = mpsc::channel(10);

        let set = DashSet::new();
        set.insert(PublicKey::from(Bytes::from(initiator_keypair.public)));

        let initiator_handshake = initiator_encrypt.initiator_handshake(&[]).unwrap();
        let frame = Frame {
            r#type: FrameType::Handshake as _,
            nonce: 0,
            data: initiator_handshake.to_vec().into(),
        };

        let from = "127.0.0.1:8888".parse().unwrap();
        let (mut encrypt_actor, frame) = EncryptActor::new(
            mailbox_sender.clone(),
            mailbox,
            udp_sender,
            tun_sender,
            responder_keypair.private.into(),
            frame,
            from,
            Duration::from_secs(10),
            &set,
            &ConnectedPeers::default(),
        )
        .unwrap();

        assert_eq!(frame.r#type(), FrameType::Handshake);

        initiator_encrypt
            .initiator_handshake_response(&frame.data)
            .unwrap();

        initiator_encrypt = initiator_encrypt.into_transport_mode().unwrap();

        tokio::spawn(async move { encrypt_actor.run().await });

        let data = FrameData {
            data_or_heartbeat: Some(DataOrHeartbeat::Data(Bytes::from_static(b"hello"))),
        }
        .encode_to_vec();
        let nonce = util::generate_nonce();
        let mut buf = vec![0; 65535];
        let n = initiator_encrypt.encrypt(nonce, &data, &mut buf).unwrap();

        let frame = Frame {
            r#type: FrameType::Transport as _,
            nonce,
            data: Bytes::copy_from_slice(&buf[..n]),
        };

        mailbox_sender
            .send(Message::Frame { frame, from })
            .await
            .unwrap();

        let tun_message = tun_mailbox.next().await.unwrap();
        match tun_message {
            TunMessage::ToTun(data) => assert_eq!(data.as_ref(), b"hello"),
            _ => panic!("inlaid tun message"),
        }

        mailbox_sender
            .send(Message::Packet(Bytes::from_static(b"world")))
            .await
            .unwrap();

        let udp_message = udp_mailbox.next().await.unwrap();
        match udp_message {
            UdpMessage::Frame { frame, to } => {
                assert_eq!(to, from);

                assert_eq!(frame.r#type(), FrameType::Transport);

                let n = initiator_encrypt
                    .decrypt(frame.nonce, &frame.data, &mut buf)
                    .unwrap();
                let frame_data = FrameData::decode(&buf[..n]).unwrap();
                assert_eq!(
                    frame_data.data_or_heartbeat,
                    Some(DataOrHeartbeat::Data(Bytes::from_static(b"world")))
                );
            }

            _ => {
                panic!("invalid udp message");
            }
        }
    }
}
