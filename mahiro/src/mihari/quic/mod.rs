use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::StreamExt;
use quinn::congestion::BbrConfig;
use quinn::{
    Connecting, Connection, ConnectionError, Endpoint, RecvStream, SendStream, ServerConfig,
    TransportConfig, VarInt,
};
use rustls::Certificate;
use tap::TapFallible;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

pub use self::common_name_auth::CommonNameAuthStore;
use super::message::TransportMessage as Message;
use super::message::TunMessage;
use super::peer_store::PeerStore;
use crate::ip_packet::{get_packet_ip, IpLocation};
use crate::util;
use crate::util::Receiver;

mod common_name_auth;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum QuicType {
    Datagram,
    Stream,
}

#[derive(Debug)]
pub struct QuicTlsConfig<'a> {
    pub ca: &'a str,
    pub key: &'a str,
    pub cert: &'a str,
}

pub struct QuicTransportActor {
    tun_sender: Sender<TunMessage>,

    endpoint: Endpoint,
    auth_store: Arc<CommonNameAuthStore>,
    peer_store: PeerStore<QuicType>,

    heartbeat_interval: Duration,
}

impl QuicTransportActor {
    pub async fn new(
        tun_sender: Sender<TunMessage>,
        auth_store: CommonNameAuthStore,
        peer_store: PeerStore<QuicType>,
        listen_addr: SocketAddr,
        QuicTlsConfig { ca, key, cert }: QuicTlsConfig<'_>,
        heartbeat_interval: Duration,
    ) -> anyhow::Result<Self> {
        let tls_server_config = util::create_tls_server_config(key, cert, Some(ca)).await?;

        info!(?tls_server_config, "create server config done");

        let mut server_config = ServerConfig::with_crypto(Arc::new(tls_server_config));
        let mut transport_config = TransportConfig::default();

        // enable bbr
        transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()));
        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::server(server_config, listen_addr)?;

        Ok(Self {
            tun_sender,
            endpoint,
            auth_store: Arc::new(auth_store),
            peer_store,
            heartbeat_interval,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let connecting = self.endpoint.accept().await.ok_or_else(|| {
                error!("quic endpoint closed");

                anyhow::anyhow!("quic endpoint closed")
            })?;

            let tun_sender = self.tun_sender.clone();
            let peer_store = self.peer_store.clone();
            let auth_store = self.auth_store.clone();

            tokio::spawn(async move {
                let mut worker =
                    QuicTransportWorker::new(connecting, auth_store, peer_store, tun_sender)
                        .await?;

                info!("create quic transport worker done");

                worker.run().await
            });
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
struct QuicTransportWorker {
    common_name: String,
    quic_type: QuicType,

    #[derivative(Debug = "ignore")]
    connection: Arc<Connection>,

    #[derivative(Debug = "ignore")]
    transport_receiver: Receiver<Message>,
    tun_sender: Sender<TunMessage>,

    auth_store: Arc<CommonNameAuthStore>,
    peer_store: PeerStore<QuicType>,
}

impl QuicTransportWorker {
    async fn new(
        connecting: Connecting,
        auth_store: Arc<CommonNameAuthStore>,
        peer_store: PeerStore<QuicType>,
        tun_sender: Sender<TunMessage>,
    ) -> anyhow::Result<Self> {
        let connection = connecting
            .await
            .tap_err(|err| error!(%err, "quic connecting wait failed"))?;

        let common_name = {
            let identity = connection.peer_identity().ok_or_else(|| {
                error!("get peer identity failed");

                anyhow::anyhow!("get peer identity failed")
            })?;
            let certs = identity.downcast_ref::<Vec<Certificate>>().ok_or_else(|| {
                error!("get peer certificates failed");

                anyhow::anyhow!("get peer certificates failed")
            })?;
            let cert = certs.get(0).ok_or_else(|| {
                error!("peer certificates is empty");

                anyhow::anyhow!("peer certificates is empty")
            })?;
            let common_name = util::parse_x509_certificate_common_name(&cert.0)?;

            info!(%common_name, "get common name done");

            if !auth_store.auth(&common_name) {
                error!(%common_name, "common name auth failed");

                connection.close(VarInt::from_u32(0), b"server failed");

                return Err(anyhow::anyhow!("common name {common_name} auth failed"));
            }

            info!(%common_name, "common name auth done");

            common_name
        };

        let quic_transport_receiver = peer_store
            .get_transport_receiver_by_identity(&common_name)
            .expect("auth done but has no quic transport receiver");

        let quic_type = peer_store
            .get_info_by_identity(&common_name)
            .expect("auth done but has no quic type");

        Ok(Self {
            common_name,
            quic_type,
            connection: Arc::new(connection),
            transport_receiver: quic_transport_receiver,
            tun_sender,
            auth_store,
            peer_store,
        })
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        match self.quic_type {
            QuicType::Datagram => self.run_datagram().await,
            QuicType::Stream => self.run_stream().await,
        }
    }

    async fn run_datagram(&self) -> anyhow::Result<()> {
        let transport_tx = self.connection.clone();
        let transport_rx = self.connection.clone();
        let tun_sender = self.tun_sender.clone();
        let peer_store = self.peer_store.clone();
        let common_name = self.common_name.clone();
        let transport_receiver = self.transport_receiver.clone();

        let mut join_set = JoinSet::new();

        join_set.spawn(Self::datagram_transport_to_tun(
            transport_rx,
            tun_sender,
            peer_store,
            common_name,
        ));
        join_set.spawn(Self::tun_to_datagram_transport(
            transport_tx,
            transport_receiver,
        ));

        if let Err(err) = join_set.join_next().await.unwrap().unwrap() {
            error!(%err, "run transport failed");

            Err(anyhow::anyhow!("run transport failed: {err}"))
        } else {
            error!("run transport stopped");

            Err(anyhow::anyhow!("run transport stopped"))
        }
    }

    async fn run_stream(&self) -> anyhow::Result<()> {
        loop {
            let (send, recv) = self
                .connection
                .accept_bi()
                .await
                .tap_err(|err| error!(%err, "accept stream failed"))?;

            let tun_sender = self.tun_sender.clone();
            let peer_store = self.peer_store.clone();
            let common_name = self.common_name.clone();
            let transport_receiver = self.transport_receiver.clone();

            tokio::spawn(async move {
                let mut join_set = JoinSet::new();

                join_set.spawn(Self::stream_transport_to_tun(
                    recv,
                    tun_sender,
                    peer_store,
                    common_name,
                ));

                join_set.spawn(Self::tun_to_stream_transport(send, transport_receiver));
            });
        }
    }

    async fn stream_transport_to_tun(
        transport_rx: RecvStream,
        tun_sender: Sender<TunMessage>,
        peer_store: PeerStore<QuicType>,
        common_name: String,
    ) -> anyhow::Result<()> {
        let mut buf = BytesMut::with_capacity(1500 * 4);
        let mut transport_rx = BufReader::new(transport_rx);

        loop {
            let mut len = transport_rx
                .read_u16()
                .await
                .tap_err(|err| error!(%err, "quic read packet len failed"))?;
            buf.reserve(len as _);

            while len > 0 {
                let n = transport_rx
                    .read_buf(&mut buf)
                    .await
                    .tap_err(|err| error!(%err, "quic read failed"))?;
                if n == 0 {
                    return Err(anyhow::anyhow!("quic connection closed"));
                }

                len -= n as u16;
            }

            let packet = buf.split().freeze();

            match get_packet_ip(&packet, IpLocation::Src) {
                None => {
                    warn!("drop not ip packet");

                    continue;
                }

                Some(src_ip) => {
                    if let IpAddr::V6(src_ip) = src_ip {
                        if src_ip.is_unicast_link_local() {
                            peer_store.update_link_local_ip(src_ip, &common_name);
                        }
                    }
                }
            }

            match tun_sender.try_send(TunMessage::ToTun(packet)) {
                Err(TrySendError::Full(_)) => {
                    warn!("tun mailbox is full, drop packet");

                    continue;
                }

                Err(err) => {
                    error!(%err, "send packet failed");

                    return Err(err.into());
                }

                Ok(_) => {}
            }
        }
    }

    async fn datagram_transport_to_tun(
        transport_rx: Arc<Connection>,
        tun_sender: Sender<TunMessage>,
        peer_store: PeerStore<QuicType>,
        common_name: String,
    ) -> anyhow::Result<()> {
        loop {
            let packet = match transport_rx.read_datagram().await {
                Err(err @ ConnectionError::ConnectionClosed(_)) => {
                    error!(%err, "quic connection aborted");

                    return Err(anyhow::anyhow!("quic connection aborted: {err}"));
                }

                Err(err @ ConnectionError::ApplicationClosed(_)) => {
                    error!(%err, "quic connection closed");

                    return Err(anyhow::anyhow!("quic connection closed: {err}"));
                }

                Err(err) => {
                    error!(%err, "quic connection failed");

                    return Err(anyhow::anyhow!("quic connection failed: {err}"));
                }

                Ok(data) => data,
            };

            match get_packet_ip(&packet, IpLocation::Src) {
                None => {
                    warn!("drop not ip packet");

                    continue;
                }

                Some(src_ip) => {
                    if let IpAddr::V6(src_ip) = src_ip {
                        if src_ip.is_unicast_link_local() {
                            peer_store.update_link_local_ip(src_ip, &common_name);
                        }
                    }
                }
            }

            match tun_sender.try_send(TunMessage::ToTun(packet)) {
                Err(TrySendError::Full(_)) => {
                    warn!("tun mailbox is full, drop packet");

                    continue;
                }

                Err(err) => {
                    error!(%err, "send packet failed");

                    return Err(err.into());
                }

                Ok(_) => {}
            }
        }
    }

    async fn tun_to_stream_transport(
        transport_tx: SendStream,
        mut quic_transport_receiver: Receiver<Message>,
    ) -> anyhow::Result<()> {
        let mut transport_tx = BufWriter::new(transport_tx);

        while let Some(Message::Packet(packet)) = quic_transport_receiver.next().await {
            transport_tx
                .write_u16(packet.len() as _)
                .await
                .tap_err(|err| error!(%err, "quic write packet len failed"))?;
            transport_tx
                .write_all(&packet)
                .await
                .tap_err(|err| error!(%err, "quic write packet failed"))?;

            transport_tx
                .flush()
                .await
                .tap_err(|err| error!(%err, "quic flush failed"))?;
        }

        Err(anyhow::anyhow!("quic_transport_receiver stopped"))
    }

    async fn tun_to_datagram_transport(
        transport_tx: Arc<Connection>,
        mut quic_transport_receiver: Receiver<Message>,
    ) -> anyhow::Result<()> {
        while let Some(Message::Packet(packet)) = quic_transport_receiver.next().await {
            transport_tx
                .send_datagram(packet)
                .tap_err(|err| error!(%err, "quic send failed"))?;
        }

        Err(anyhow::anyhow!("quic_transport_receiver stopped"))
    }
}
