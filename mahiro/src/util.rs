use std::task::Poll;
use std::{future, io};

use aya::programs::tc::SchedClassifierLink;
use aya::programs::xdp::XdpLink;
use aya::programs::Link;
use flume::r#async::RecvStream;
use rand::{thread_rng, Rng};
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;

/// flume 'static RecvStream alias
pub type Receiver<T> = RecvStream<'static, T>;

pub fn generate_nonce() -> u64 {
    thread_rng().gen()
}

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
