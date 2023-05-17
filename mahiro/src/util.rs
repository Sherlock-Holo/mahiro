use flume::r#async::RecvStream;
use rand::{thread_rng, Rng};

/// flume 'static RecvStream alias
pub type Receiver<T> = RecvStream<'static, T>;

pub fn generate_nonce() -> u64 {
    thread_rng().gen()
}
