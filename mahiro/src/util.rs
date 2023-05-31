use std::io;
use std::time::SystemTime;

use async_signal::{Signal, Signals};
use aya::programs::tc::SchedClassifierLink;
use aya::programs::xdp::XdpLink;
use aya::programs::Link;
use flume::r#async::RecvStream;
use futures_util::StreamExt;
use rand::{thread_rng, Rng};
use ring_io::runtime;
use ring_io::runtime::Builder;

/// flume 'static RecvStream alias
pub type Receiver<T> = RecvStream<'static, T>;

pub fn generate_nonce() -> u64 {
    thread_rng().gen()
}

pub fn generate_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as _
}

pub async fn stop_signal() -> io::Result<()> {
    let mut signals = Signals::new([Signal::Term, Signal::Int])?;

    signals.next().await.unwrap().map(|_| ())
}

pub fn io_uring_builder() -> Builder {
    let mut builder = runtime::create_io_uring_builder();
    builder
        .dontfork()
        .setup_single_issuer()
        .setup_defer_taskrun();

    builder
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
