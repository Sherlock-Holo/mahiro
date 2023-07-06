use std::cmp::Ordering;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use std::{future, io};

use aya::programs::tc::SchedClassifierLink;
use aya::programs::xdp::XdpLink;
use aya::programs::Link;
use flume::r#async::RecvStream;
use quinn::congestion::BbrConfig;
use quinn::{IdleTimeout, MtuDiscoveryConfig, TransportConfig};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerConfig,
};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use tap::TapFallible;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tokio::{fs, net};
use tracing::error;
use webpki::TrustAnchor;

/// 20 MiB
pub const INITIAL_WINDOW_SIZE: u32 = 20 * 1024 * 1024;
/// 100 MiB
pub const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 100 * 1024 * 1024;
/// the h2 lib allowed max size
pub const MAX_FRAME_SIZE: u32 = 16777215;
/// h2 transport count
pub const HTTP2_TRANSPORT_COUNT: u8 = 1;
/// websocket transport count
pub const WEBSOCKET_TRANSPORT_COUNT: u8 = 4;
/// transport public id header
pub const PUBLIC_ID_HEADER: &str = "x-mahiro-public";
/// transport hmac header
pub const HMAC_HEADER: &str = "x-mahiro-mac";

/// flume 'static RecvStream alias
pub type Receiver<T> = RecvStream<'static, T>;

pub async fn stop_signal() -> io::Result<()> {
    let mut signal_terminate = unix::signal(SignalKind::terminate())?;
    let mut signal_interrupt = unix::signal(SignalKind::interrupt())?;

    future::poll_fn(|cx| {
        if signal_terminate.poll_recv(cx).is_ready() {
            return Poll::Ready(());
        }

        signal_interrupt.poll_recv(cx).map(|_| ())
    })
    .await;

    Ok(())
}

pub async fn create_tls_client_config(
    key_and_cert: Option<(&str, &str)>,
    ca: Option<&str>,
) -> anyhow::Result<ClientConfig> {
    let store = build_root_cert_store(ca).await?;
    let client_config = match key_and_cert {
        None => ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(store)
            .with_no_client_auth(),
        Some((key, cert)) => {
            let mut keys = load_keys(key).await?;
            let certs = load_certs(cert).await?;

            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(store)
                .with_single_cert(certs, keys.remove(0))?
        }
    };

    Ok(client_config)
}

pub async fn create_tls_server_config(
    key: &str,
    cert: &str,
    ca: Option<&str>,
) -> anyhow::Result<ServerConfig> {
    let store = build_root_cert_store(ca).await?;
    let mut keys = load_keys(key).await?;
    let certs = load_certs(cert).await?;

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(store)))
        .with_single_cert(certs, keys.remove(0))?;

    Ok(server_config)
}

async fn build_root_cert_store(ca: Option<&str>) -> anyhow::Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        store.add(&Certificate(cert.0))?;
    }

    if let Some(ca) = ca {
        let ca_cert = fs::read(ca).await?;
        let ca_certs = rustls_pemfile::certs(&mut ca_cert.as_slice())?;

        let ca_certs = ca_certs
            .iter()
            .map(|cert| {
                let ta = TrustAnchor::try_from_cert_der(cert)?;

                Ok::<_, anyhow::Error>(OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        store.add_server_trust_anchors(ca_certs.into_iter());
    }

    Ok(store)
}

pub async fn load_certs(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let certs = fs::read(path).await?;
    let mut certs = rustls_pemfile::certs(&mut certs.as_slice())?;

    Ok(certs.drain(..).map(Certificate).collect())
}

pub async fn load_keys(path: &str) -> anyhow::Result<Vec<PrivateKey>> {
    let keys = fs::read(path).await?;
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut keys.as_slice())?;

    Ok(keys.drain(..).map(PrivateKey).collect())
}

pub async fn dns_lookup(addr: &str) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = net::lookup_host(addr)
        .await
        .tap_err(|err| error!(%err, "dns lookup failed"))?
        .collect::<Vec<_>>();
    addrs.sort_by(|addr1, addr2| {
        if addr1.is_ipv6() && addr2.is_ipv4() {
            Ordering::Less
        } else if addr1.is_ipv4() && addr2.is_ipv6() {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });

    Ok(addrs)
}

pub fn parse_x509_certificate_common_name(cert: &[u8]) -> anyhow::Result<String> {
    let cert = x509_parser::parse_x509_certificate(cert)
        .tap_err(|err| error!(%err, "parse x509 certificate failed"))?;

    let common_name = cert
        .1
        .subject()
        .iter_common_name()
        .map(|value| value.as_str().map(|cn| cn.to_string()))
        .next();

    match common_name {
        None => {
            error!("no common name found");

            Err(anyhow::anyhow!("no common name found"))
        }

        Some(Err(err)) => {
            error!(%err, "parse common name failed");

            Err(anyhow::anyhow!("parse common name failed: {err}"))
        }

        Some(Ok(common_name)) => Ok(common_name),
    }
}

pub fn parse_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    humantime::parse_duration(&string).map_err(Error::custom)
}

pub fn parse_option_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let string = Option::<String>::deserialize(deserializer)?;
    string
        .map(|string| humantime::parse_duration(&string).map_err(Error::custom))
        .transpose()
}

pub fn build_quic_transport_config(heartbeat_interval: Duration) -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    // enable bbr and set keepalive
    transport_config
        .congestion_controller_factory(Arc::new(BbrConfig::default()))
        .max_idle_timeout(Some(IdleTimeout::try_from(heartbeat_interval * 2).unwrap()))
        .keep_alive_interval(Some(heartbeat_interval))
        .mtu_discovery_config(Some(MtuDiscoveryConfig::default()));

    transport_config
}

#[derive(Debug)]
pub struct OwnedLink<T: Link>(Option<T>);

impl From<SchedClassifierLink> for OwnedLink<SchedClassifierLink> {
    fn from(value: SchedClassifierLink) -> Self {
        Self(Some(value))
    }
}

impl From<XdpLink> for OwnedLink<XdpLink> {
    fn from(value: XdpLink) -> Self {
        Self(Some(value))
    }
}

impl<T: Link> Drop for OwnedLink<T> {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().detach();
    }
}
