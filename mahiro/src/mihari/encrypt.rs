use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::{Duration, Instant};

use bytes::Bytes;
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use prost::Message as _;
use tap::TapFallible;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use super::message::EncryptMessage as Message;
use super::message::{TunMessage, UdpMessage};
use super::peer_store::PeerStore;
use crate::cookie::COOKIE_LENGTH;
use crate::encrypt::Encrypt;
use crate::ip_packet::{get_packet_ip, IpLocation};
use crate::protocol::frame_data::DataOrHeartbeat;
use crate::protocol::{Frame, FrameData, FrameType};
use crate::public_key::PublicKey;
use crate::timestamp::generate_timestamp;
use crate::util::Receiver;
use crate::{util, HEARTBEAT_DATA};

type Cookie = PublicKey;

#[derive(Derivative)]
#[derivative(Debug)]
enum State {
    Transport {
        cookie: Cookie,
        encrypt: Arc<Encrypt>,
        heartbeat_receive_instant: Arc<RwLock<Instant>>,
        peer_store: PeerStore,
        latest_timestamp: Arc<AtomicU64>,
        has_save_link_local_ipv6: Arc<AtomicBool>,
    },
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct EncryptActor {
    mailbox_sender: Sender<Message>,
    #[derivative(Debug = "ignore")]
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
        heartbeat_interval: Duration,
        peer_store: &PeerStore,
    ) -> anyhow::Result<(Self, Frame)> {
        if frame.cookie.len() != COOKIE_LENGTH {
            error!("drop invalid length cookie frame");

            return Err(anyhow::anyhow!(
                "invalid cookie length {}",
                frame.cookie.len()
            ));
        }

        match frame.r#type() {
            FrameType::Transport => {
                error!("unexpected transport frame");

                Err(anyhow::anyhow!("unexpected transport frame"))
            }
            FrameType::Handshake => {
                let mut encrypt = Encrypt::new_responder(&local_private_key)
                    .tap_err(|err| error!(%err, "create responder encrypt failed"))?;

                let responder_handshake_success = encrypt.responder_handshake(&frame.data)?;

                let (mahiro_ipv4, mahiro_ipv6) = match peer_store
                    .get_mahiro_ip_by_public_key(responder_handshake_success.peer_public_key)
                {
                    None => {
                        error!("unknown public key");

                        return Err(anyhow::anyhow!("unknown public key"));
                    }

                    Some(ip) => ip,
                };

                if responder_handshake_success.payload.len() != 8 {
                    error!("invalid handshake timestamp payload");

                    return Err(anyhow::anyhow!("invalid handshake timestamp payload"));
                }

                let timestamp =
                    u64::from_be_bytes(responder_handshake_success.payload.try_into().unwrap());

                let response = encrypt.responder_handshake_response(&[])?;
                let handshake_response_frame = Frame {
                    cookie: frame.cookie.clone(),
                    r#type: FrameType::Handshake as _,
                    nonce: 0,
                    data: Bytes::copy_from_slice(response),
                };

                encrypt = encrypt.into_transport_mode()?;

                // make sure tun actor can find this encrypt actor
                peer_store.add_mahiro_ip(mahiro_ipv4.into(), mailbox_sender.clone());
                peer_store.add_mahiro_ip(mahiro_ipv6.into(), mailbox_sender.clone());

                Ok((
                    Self {
                        mailbox_sender,
                        mailbox,
                        udp_sender,
                        tun_sender,
                        state: State::Transport {
                            cookie: frame.cookie.into(),
                            encrypt: Arc::new(encrypt),
                            heartbeat_receive_instant: Arc::new(RwLock::new(Instant::now())),
                            peer_store: peer_store.clone(),
                            latest_timestamp: Arc::new(AtomicU64::new(timestamp)),
                            has_save_link_local_ipv6: Arc::new(AtomicBool::new(false)),
                        },
                        heartbeat_interval,
                    },
                    handshake_response_frame,
                ))
            }
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut tasks = FuturesUnordered::new();

        match &self.state {
            State::Transport {
                cookie,
                encrypt,
                heartbeat_receive_instant,
                peer_store,
                latest_timestamp,
                has_save_link_local_ipv6,
            } => {
                let parallel = available_parallelism()
                    .unwrap_or(NonZeroUsize::new(4).unwrap())
                    .get();
                let heartbeat_interval = self.heartbeat_interval;
                let mailbox_sender = self.mailbox_sender.clone();
                for _ in 0..parallel {
                    let mut encrypt_actor_transport_inner = EncryptActorTransportInner {
                        mailbox_sender: mailbox_sender.clone(),
                        mailbox: self.mailbox.clone(),
                        udp_sender: self.udp_sender.clone(),
                        tun_sender: self.tun_sender.clone(),
                        cookie: cookie.clone(),
                        encrypt: encrypt.clone(),
                        buffer: vec![0; 65535],
                        heartbeat_receive_instant: heartbeat_receive_instant.clone(),
                        heartbeat_interval,
                        peer_store: peer_store.clone(),
                        latest_timestamp: latest_timestamp.clone(),
                        has_save_link_local_ipv6: has_save_link_local_ipv6.clone(),
                    };

                    tasks.push(ring_io::spawn(async move {
                        encrypt_actor_transport_inner.run().await
                    }));
                }

                tasks.push(ring_io::spawn(async move {
                    Self::heartbeat(heartbeat_interval, mailbox_sender).await;

                    Ok(())
                }));

                while let Some(result) = tasks.next().await {
                    if let Err(err) = result {
                        error!(%err, "encrypt actor transport inner run failed");

                        return Err(err);
                    }
                }

                Err(anyhow::anyhow!("encrypt actor transport inner stopped"))
            }
        }
    }

    async fn heartbeat(heartbeat_interval: Duration, mailbox_sender: Sender<Message>) {
        let mut interval = async_timer::interval(heartbeat_interval);
        while interval.next().await.is_some() {
            if let Err(err @ TrySendError::Disconnected(_)) =
                mailbox_sender.try_send(Message::Heartbeat)
            {
                error!(%err, "send heartbeat message failed");
            }
        }
    }
}

struct HandleTransportFrameArgs<'a> {
    frame: Frame,
    from: SocketAddr,
    buffer: &'a mut [u8],
    encrypt: &'a Encrypt,
    heartbeat_receive_instant: &'a RwLock<Instant>,
    mailbox_sender: &'a mut Sender<Message>,
    udp_sender: &'a mut Sender<UdpMessage>,
    tun_sender: &'a mut Sender<TunMessage>,
    peer_store: &'a PeerStore,
    latest_timestamp: &'a AtomicU64,
    has_save_link_local_ipv6: &'a AtomicBool,
}

fn get_peer_addr_by_cookie(
    connected_peers: &PeerStore,
    cookie: &Bytes,
) -> anyhow::Result<SocketAddr> {
    match connected_peers.get_peer_info_by_cookie(cookie) {
        None => {
            error!("peer info miss, encrypt actor in invalid status");

            Err(anyhow::anyhow!(
                "peer info miss, encrypt actor in invalid status"
            ))
        }

        Some(peer_info) => Ok(peer_info.addr),
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
struct EncryptActorTransportInner {
    mailbox_sender: Sender<Message>,
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    udp_sender: Sender<UdpMessage>,
    tun_sender: Sender<TunMessage>,
    cookie: Cookie,
    encrypt: Arc<Encrypt>,
    #[derivative(Debug = "ignore")]
    buffer: Vec<u8>,
    heartbeat_receive_instant: Arc<RwLock<Instant>>,
    heartbeat_interval: Duration,
    peer_store: PeerStore,
    latest_timestamp: Arc<AtomicU64>,
    has_save_link_local_ipv6: Arc<AtomicBool>,
}

impl EncryptActorTransportInner {
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.run_circle().await?;
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

        match message {
            Message::Packet(packet) => {
                let remote_addr = get_peer_addr_by_cookie(&self.peer_store, &self.cookie)?;

                Self::handle_transport_packet(
                    &self.cookie,
                    packet,
                    remote_addr,
                    &mut self.buffer,
                    &self.encrypt,
                    &self.udp_sender,
                )
                .await?;

                debug!("handle transport packet done");

                Ok(())
            }

            Message::Frame { frame, from } => {
                Self::handle_transport_frame(HandleTransportFrameArgs {
                    frame,
                    from,
                    buffer: &mut self.buffer,
                    encrypt: &self.encrypt,
                    heartbeat_receive_instant: &self.heartbeat_receive_instant,
                    mailbox_sender: &mut self.mailbox_sender,
                    udp_sender: &mut self.udp_sender,
                    tun_sender: &mut self.tun_sender,
                    peer_store: &self.peer_store,
                    latest_timestamp: &self.latest_timestamp,
                    has_save_link_local_ipv6: &self.has_save_link_local_ipv6,
                })
                .await?;

                debug!("handle transport frame done");

                Ok(())
            }

            Message::Heartbeat => {
                let remote_addr = get_peer_addr_by_cookie(&self.peer_store, &self.cookie)?;

                Self::handle_transport_heartbeat(
                    &self.cookie,
                    &mut self.buffer,
                    remote_addr,
                    &self.encrypt,
                    self.heartbeat_interval,
                    &self.heartbeat_receive_instant,
                    &mut self.udp_sender,
                )
                .await?;

                debug!("handle transport heartbeat done");

                Ok(())
            }
        }
    }

    async fn handle_transport_packet(
        cookie: &Bytes,
        packet: Bytes,
        to: SocketAddr,
        buffer: &mut [u8],
        encrypt: &Encrypt,
        udp_sender: &Sender<UdpMessage>,
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

        match udp_sender.try_send(UdpMessage::Frame { frame, to }) {
            Err(TrySendError::Full(_)) => {
                warn!("udp actor mailbox full");

                Ok(())
            }

            Err(err) => {
                error!(%err, "send frame failed");

                Err(err.into())
            }

            Ok(_) => Ok(()),
        }
    }

    async fn handle_transport_frame(
        HandleTransportFrameArgs {
            frame,
            from,
            buffer,
            encrypt,
            heartbeat_receive_instant,
            mailbox_sender,
            udp_sender,
            tun_sender,
            peer_store,
            latest_timestamp,
            has_save_link_local_ipv6,
        }: HandleTransportFrameArgs<'_>,
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

                        return Ok(());
                    }

                    Some(DataOrHeartbeat::Pong(data) | DataOrHeartbeat::Ping(data)) => {
                        if data != HEARTBEAT_DATA {
                            error!("invalid heartbeat data");

                            return Ok(());
                        }

                        if matches!(frame_data.data_or_heartbeat, Some(DataOrHeartbeat::Pong(_))) {
                            *heartbeat_receive_instant.write().await = Instant::now();
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
                                cookie: frame.cookie.clone(),
                                r#type: FrameType::Transport as _,
                                nonce,
                                data: pong_data,
                            };

                            match udp_sender.try_send(UdpMessage::Frame { frame, to: from }) {
                                Err(TrySendError::Full(_)) => {
                                    warn!("udp actor mailbox full");
                                }

                                Err(err) => {
                                    error!(%err, "send pong frame failed");

                                    return Err(err.into());
                                }

                                Ok(_) => {}
                            }
                        }
                    }

                    Some(DataOrHeartbeat::Data(data)) => {
                        // also update heartbeat instant, because we receive the data frame, means
                        // peer is alive
                        *heartbeat_receive_instant.write().await = Instant::now();

                        if !has_save_link_local_ipv6.load(Ordering::Acquire) {
                            match get_packet_ip(data, IpLocation::Src) {
                                None => {
                                    error!("drop not ip packet");

                                    return Ok(());
                                }

                                Some(src_ip) => {
                                    if let IpAddr::V6(src_ip) = src_ip {
                                        if src_ip.is_unicast_link_local() {
                                            peer_store.add_mahiro_ip(
                                                src_ip.into(),
                                                mailbox_sender.clone(),
                                            );

                                            has_save_link_local_ipv6.store(true, Ordering::Release);
                                        }
                                    }
                                }
                            }
                        }

                        match tun_sender.try_send(TunMessage::ToTun(data.clone())) {
                            Err(TrySendError::Full(_)) => {
                                warn!("tun mailbox is full, drop packet");

                                return Ok(());
                            }

                            Err(err) => {
                                error!(%err, "send packet failed");

                                return Err(err.into());
                            }

                            Ok(_) => {}
                        }
                    }
                }

                let old_timestamp = latest_timestamp.load(Ordering::Acquire);
                if frame_data.timestamp > old_timestamp
                    && latest_timestamp
                        .compare_exchange(
                            old_timestamp,
                            frame_data.timestamp,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                {
                    if let Some(old_addr) = peer_store.update_peer_addr(&frame.cookie, from) {
                        info!(%old_addr, new_addr = %from, "peer update addr done");
                    }
                }

                Ok(())
            }
        }
    }

    async fn handle_transport_heartbeat(
        cookie: &Bytes,
        buffer: &mut [u8],
        to: SocketAddr,
        encrypt: &Encrypt,
        heartbeat_interval: Duration,
        heartbeat_receive_instant: &RwLock<Instant>,
        udp_sender: &mut Sender<UdpMessage>,
    ) -> anyhow::Result<()> {
        if heartbeat_receive_instant.read().await.elapsed() > heartbeat_interval * 2 {
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

        match udp_sender.try_send(UdpMessage::Frame { frame, to }) {
            Err(TrySendError::Full(_)) => {
                warn!("udp actor mailbox full");

                Ok(())
            }

            Err(err) => {
                error!(%err, "send udp heartbeat frame failed");

                Err(err.into())
            }

            Ok(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use futures_util::SinkExt;
    use test_log::test;

    use super::*;
    use crate::cookie::generate_cookie;

    #[test]
    fn test() {
        ring_io::block_on(async move {
            let initiator_keypair = Encrypt::generate_keypair().unwrap();
            let responder_keypair = Encrypt::generate_keypair().unwrap();
            let mut initiator_encrypt =
                Encrypt::new_initiator(&initiator_keypair.private, &responder_keypair.public)
                    .unwrap();
            let (tun_sender, tun_mailbox) = flume::bounded(10);
            let (udp_sender, udp_mailbox) = flume::bounded(10);
            let (mailbox_sender, mailbox) = flume::bounded(10);

            let cookie = generate_cookie();
            let timestamp = generate_timestamp().to_be_bytes();
            let initiator_handshake = initiator_encrypt.initiator_handshake(&timestamp).unwrap();
            let frame = Frame {
                cookie: cookie.clone(),
                r#type: FrameType::Handshake as _,
                nonce: 0,
                data: initiator_handshake.to_vec().into(),
            };

            let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
            let ipv6 = Ipv6Addr::from_str("fc00:100::1").unwrap();
            let peer_store = PeerStore::from([(initiator_keypair.public.into(), (ipv4, ipv6))]);
            let from = "127.0.0.1:8888".parse().unwrap();
            peer_store.add_peer_info(cookie.clone(), from, mailbox_sender.clone());
            let (mut encrypt_actor, frame) = EncryptActor::new(
                mailbox_sender.clone(),
                mailbox.into_stream(),
                udp_sender,
                tun_sender,
                responder_keypair.private.into(),
                frame,
                Duration::from_secs(10),
                &peer_store,
            )
            .unwrap();

            assert_eq!(frame.r#type(), FrameType::Handshake);

            initiator_encrypt
                .initiator_handshake_response(&frame.data)
                .unwrap();

            initiator_encrypt = initiator_encrypt.into_transport_mode().unwrap();

            ring_io::spawn(async move { encrypt_actor.run().await }).detach();

            let mut tun_mailbox = tun_mailbox.into_stream();
            let mut udp_mailbox = udp_mailbox.into_stream();
            let mut mailbox_sender = mailbox_sender.into_sink();

            let data = FrameData {
                timestamp: generate_timestamp(),
                data_or_heartbeat: Some(DataOrHeartbeat::Data(Bytes::from_static(b"hello"))),
            }
            .encode_to_vec();
            let nonce = util::generate_nonce();
            let mut buf = vec![0; 65535];
            let n = initiator_encrypt.encrypt(nonce, &data, &mut buf).unwrap();

            let frame = Frame {
                cookie,
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

            peer_store.get_sender_by_mahiro_ip(ipv4.into()).unwrap();
            peer_store.get_sender_by_mahiro_ip(ipv6.into()).unwrap();
        })
    }
}
