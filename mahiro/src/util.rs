use std::task::Poll;
use std::{future, io};

use aya::programs::tc::SchedClassifierLink;
use aya::programs::xdp::XdpLink;
use aya::programs::Link;
use flume::r#async::RecvStream;
use rustls::{Certificate, PrivateKey};
use tokio::fs;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;

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
