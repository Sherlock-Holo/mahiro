use rand::{thread_rng, Rng};

pub fn generate_nonce() -> u64 {
    thread_rng().gen()
}
