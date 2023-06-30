use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::{StreamExt, TryStreamExt};
use http::Uri;
use quinn::congestion::BbrConfig;
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, IdleTimeout, RecvStream, SendStream,
    TransportConfig,
};
use tap::TapFallible;
use tokio::task::JoinSet;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, instrument, warn};

use super::message::TransportMessage as Message;
use super::message::TunMessage;
use crate::quic_stream_codec::{QuicStreamDecoder, QuicStreamEncoder};
use crate::util::{self, Receiver};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum QuicType {
    Datagram,
    Stream,
}

#[derive(Debug)]
pub struct QuicTlsConfig<'a> {
    pub ca: Option<&'a str>,
    pub key: &'a str,
    pub cert: &'a str,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct QuicTransportActor {
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    tun_sender: Sender<TunMessage>,

    #[derivative(Debug = "ignore")]
    endpoint: Endpoint,

    remote_domain: String,
    domain_and_port: String,
    heartbeat_interval: Duration,
    quic_type: QuicType,
    transport_count: u8,
}

impl QuicTransportActor {
    pub async fn new(
        QuicTlsConfig { ca, key, cert }: QuicTlsConfig<'_>,
        remote_addr: &str,
        heartbeat_interval: Duration,
        mailbox: Receiver<Message>,
        tun_sender: Sender<TunMessage>,
        quic_type: QuicType,
    ) -> anyhow::Result<Self> {
        let remote_addr: Uri = remote_addr
            .parse()
            .tap_err(|err| error!(%err, %remote_addr, "parse remote addr as uri failed"))?;
        let remote_domain = remote_addr.host().ok_or_else(|| {
            error!(%remote_addr, "no host found");

            anyhow::anyhow!("no host found")
        })?;
        if remote_addr.port_u16().is_none() {
            error!(%remote_addr, "no port found");

            return Err(anyhow::anyhow!("no port found"));
        }
        let domain_and_port = remote_addr.authority().unwrap().as_str();

        let client_config = util::create_tls_client_config(Some((key, cert)), ca).await?;
        let mut client_config = ClientConfig::new(Arc::new(client_config));
        let mut transport_config = TransportConfig::default();

        // enable bbr and set keepalive
        transport_config
            .congestion_controller_factory(Arc::new(BbrConfig::default()))
            .max_idle_timeout(Some(IdleTimeout::try_from(heartbeat_interval * 2).unwrap()))
            .keep_alive_interval(Some(heartbeat_interval));
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = Endpoint::client(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))
            .tap_err(|err| error!(%err, "bind endpoint failed"))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            mailbox,
            tun_sender,
            endpoint,
            remote_domain: remote_domain.to_string(),
            domain_and_port: domain_and_port.to_string(),
            heartbeat_interval,
            quic_type,
            transport_count: 1,
        })
    }

    async fn connect(
        endpoint: &Endpoint,
        addrs: &[SocketAddr],
        service_name: &str,
    ) -> anyhow::Result<Connection> {
        let mut last_err: Option<anyhow::Error> = None;
        for &addr in addrs {
            match endpoint.connect(addr, service_name) {
                Err(err) => {
                    warn!(%err, %addr, service_name, "connect addr failed, try next addr");

                    last_err = Some(err.into());
                }

                Ok(connecting) => match connecting.await {
                    Err(err) => {
                        warn!(%err, %addr, service_name, "wait connecting done failed, try next addr");

                        last_err = Some(err.into());
                    }

                    Ok(connection) => return Ok(connection),
                },
            }
        }

        let err = last_err.unwrap();

        error!(%err, ?addrs, "connect failed");

        Err(err)
    }

    pub async fn run(&mut self) {
        loop {
            if let Err(err) = self.run_circle().await {
                error!(%err, "quic actor run circle failed");
            }
        }
    }

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        match self.quic_type {
            QuicType::Datagram => self.run_datagram_circle().await,
            QuicType::Stream => self.run_stream_circle().await,
        }
    }

    async fn run_datagram_circle(&mut self) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();

        for _ in 0..self.transport_count {
            let connection = self
                .open_datagram_transport()
                .await
                .tap_err(|err| error!(%err, "open datagram transport failed"))?;
            let mailbox = self.mailbox.clone();
            let tun_sender = self.tun_sender.clone();

            join_set.spawn(async move {
                Self::run_datagram_transport(Arc::new(connection), tun_sender, mailbox).await
            });
        }

        join_set.join_next().await.unwrap().unwrap();

        join_set.shutdown().await;

        Err(anyhow::anyhow!("quic actor stopped"))
    }

    async fn run_stream_circle(&mut self) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();

        for _ in 0..self.transport_count {
            let (transport_tx, transport_rx) = self
                .open_stream_transport()
                .await
                .tap_err(|err| error!(%err, "open stream transport failed"))?;
            let mailbox = self.mailbox.clone();
            let tun_sender = self.tun_sender.clone();

            join_set.spawn(async move {
                Self::run_stream_transport(transport_tx, transport_rx, tun_sender, mailbox).await
            });
        }

        join_set.join_next().await.unwrap().unwrap();

        join_set.shutdown().await;

        Err(anyhow::anyhow!("quic actor stopped"))
    }

    #[instrument(err)]
    async fn open_datagram_transport(&self) -> anyhow::Result<Connection> {
        let addrs = util::dns_lookup(&self.domain_and_port).await.tap_err(
            |err| error!(%err, domain_and_port = %self.domain_and_port, "dns lookup failed"),
        )?;

        info!(?addrs, "dns lookup done");

        let connection = Self::connect(&self.endpoint, &addrs, &self.remote_domain).await?;

        info!(remote_domain = %self.remote_domain, ?addrs, "connect done");

        Ok(connection)
    }

    #[instrument(err)]
    async fn open_stream_transport(&self) -> anyhow::Result<(SendStream, RecvStream)> {
        let addrs = util::dns_lookup(&self.domain_and_port).await.tap_err(
            |err| error!(%err, domain_and_port = %self.domain_and_port, "dns lookup failed"),
        )?;

        info!(?addrs, "dns lookup done");

        let connection = Self::connect(&self.endpoint, &addrs, &self.remote_domain).await?;

        info!(remote_domain = %self.remote_domain, ?addrs, "connect done");

        let (send, recv) = connection
            .open_bi()
            .await
            .tap_err(|err| error!(%err, "open quic stream failed"))?;

        Ok((send, recv))
    }

    async fn run_datagram_transport(
        transport_tx: Arc<Connection>,
        tun_sender: Sender<TunMessage>,
        mut mailbox: Receiver<Message>,
    ) {
        let mut join_set = JoinSet::new();
        let transport_rx = transport_tx.clone();
        join_set.spawn(async move {
            loop {
                let data = match transport_rx.read_datagram().await {
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

                if let Err(TrySendError::Disconnected(_)) =
                    tun_sender.try_send(TunMessage::ToTun(data))
                {
                    error!("tun sender disconnected");

                    return Err(anyhow::anyhow!("tun sender disconnected"));
                }
            }
        });

        join_set.spawn(async move {
            while let Some(Message::Packet(packet)) = mailbox.next().await {
                transport_tx
                    .send_datagram(packet)
                    .tap_err(|err| error!(%err, "quic send failed"))?;
            }

            Ok(())
        });

        if let Err(err) = join_set.join_next().await.unwrap().unwrap() {
            error!(%err, "transport stopped with error");
        } else {
            info!("transport stopped");
        }

        join_set.shutdown().await;
    }

    async fn run_stream_transport(
        transport_tx: SendStream,
        transport_rx: RecvStream,
        tun_sender: Sender<TunMessage>,
        mailbox: Receiver<Message>,
    ) {
        let mut join_set = JoinSet::new();
        join_set.spawn(async move {
            let mut transport_rx = FramedRead::new(transport_rx, QuicStreamDecoder::default());

            while let Some(packet) = transport_rx
                .try_next()
                .await
                .tap_err(|err| error!(%err, "quic read packet failed"))?
            {
                if let Err(TrySendError::Disconnected(_)) =
                    tun_sender.try_send(TunMessage::ToTun(packet))
                {
                    error!("tun sender disconnected");

                    return Err(anyhow::anyhow!("tun sender disconnected"));
                }
            }

            Err(anyhow::anyhow!("quic connection closed"))
        });

        join_set.spawn(async move {
            let transport_tx = FramedWrite::new(transport_tx, QuicStreamEncoder::default());

            mailbox
                .map(|Message::Packet(packet)| Ok(packet))
                .forward(transport_tx)
                .await
                .tap_err(|err| error!(%err, "quic send packet failed"))?;

            Ok(())
        });

        if let Err(err) = join_set.join_next().await.unwrap().unwrap() {
            error!(%err, "transport stopped with error");
        } else {
            info!("transport stopped");
        }

        join_set.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use bytes::Bytes;
    use quinn::ServerConfig;
    use rustls::Certificate;
    use test_log::test;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time as tokio_time;

    use super::*;

    #[test(tokio::test)]
    async fn test_datagram() {
        const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12010);
        const HEARTBEAT: Duration = Duration::from_secs(5);

        let tls_server_config = create_tls_server_config().await.unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::with_crypto(Arc::new(tls_server_config)),
            LISTEN_ADDR,
        )
        .unwrap();

        let (data_tx, data_rx) = flume::bounded(1);

        tokio::spawn(async move {
            let connecting = server_endpoint.accept().await.unwrap();
            let connection = connecting.await.unwrap();

            {
                let peer_identity = connection.peer_identity().unwrap();
                let certs = peer_identity.downcast_ref::<Vec<Certificate>>().unwrap();

                assert_eq!(
                    util::parse_x509_certificate_common_name(&certs[0].0).unwrap(),
                    "holo"
                );
            }

            connection
                .send_datagram(Bytes::from_static(b"test"))
                .unwrap();
            let data = connection.read_datagram().await.unwrap();
            data_tx.send_async(data).await.unwrap();

            // wait send datagram done
            tokio_time::sleep(Duration::from_millis(100)).await;

            server_endpoint.wait_idle().await;
        });

        let (quic_transport_sender, quic_transport_mailbox) = flume::unbounded();
        let (tun_sender, tun_mailbox) = flume::unbounded();
        let mut quic_transport_actor = QuicTransportActor::new(
            QuicTlsConfig {
                ca: Some("../testdata/ca.cert"),
                key: "../testdata/client.key",
                cert: "../testdata/client.cert",
            },
            "localhost:12010",
            HEARTBEAT,
            quic_transport_mailbox.into_stream(),
            tun_sender,
            QuicType::Datagram,
        )
        .await
        .unwrap();

        tokio::spawn(async move { quic_transport_actor.run().await });

        quic_transport_sender
            .send_async(Message::Packet(Bytes::from_static(b"test")))
            .await
            .unwrap();

        let TunMessage::ToTun(tun_packet) = tun_mailbox.recv_async().await.unwrap();
        assert_eq!(tun_packet.as_ref(), b"test");
        let body = data_rx.recv_async().await.unwrap();
        assert_eq!(body.as_ref(), b"test");
    }

    #[test(tokio::test)]
    async fn test_stream() {
        const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12011);
        const HEARTBEAT: Duration = Duration::from_secs(5);

        let tls_server_config = create_tls_server_config().await.unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::with_crypto(Arc::new(tls_server_config)),
            LISTEN_ADDR,
        )
        .unwrap();

        let (data_tx, data_rx) = flume::bounded(1);

        tokio::spawn(async move {
            let connecting = server_endpoint.accept().await.unwrap();
            let connection = connecting.await.unwrap();

            {
                let peer_identity = connection.peer_identity().unwrap();
                let certs = peer_identity.downcast_ref::<Vec<Certificate>>().unwrap();

                assert_eq!(
                    util::parse_x509_certificate_common_name(&certs[0].0).unwrap(),
                    "holo"
                );
            }

            let (mut tx, mut rx) = connection.accept_bi().await.unwrap();

            tx.write_u16(4).await.unwrap();
            tx.write_all(b"test").await.unwrap();

            let len = rx.read_u16().await.unwrap();
            let mut buf = vec![0; len as _];
            rx.read_exact(&mut buf).await.unwrap();

            data_tx.send_async(Bytes::from(buf)).await.unwrap();

            server_endpoint.wait_idle().await;
        });

        let (quic_transport_sender, quic_transport_mailbox) = flume::unbounded();
        let (tun_sender, tun_mailbox) = flume::unbounded();
        let mut quic_transport_actor = QuicTransportActor::new(
            QuicTlsConfig {
                ca: Some("../testdata/ca.cert"),
                key: "../testdata/client.key",
                cert: "../testdata/client.cert",
            },
            "localhost:12011",
            HEARTBEAT,
            quic_transport_mailbox.into_stream(),
            tun_sender,
            QuicType::Stream,
        )
        .await
        .unwrap();

        tokio::spawn(async move { quic_transport_actor.run().await });

        quic_transport_sender
            .send_async(Message::Packet(Bytes::from_static(b"test")))
            .await
            .unwrap();

        let TunMessage::ToTun(tun_packet) = tun_mailbox.recv_async().await.unwrap();
        assert_eq!(tun_packet.as_ref(), b"test");
        let body = data_rx.recv_async().await.unwrap();
        assert_eq!(body.as_ref(), b"test");
    }

    async fn create_tls_server_config() -> anyhow::Result<rustls::ServerConfig> {
        util::create_tls_server_config(
            "../testdata/server.key",
            "../testdata/server.cert",
            Some("../testdata/ca.cert"),
        )
        .await
    }
}
