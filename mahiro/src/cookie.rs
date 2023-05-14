use bytes::Bytes;
use rand::{thread_rng, Rng};

pub const COOKIE_LENGTH: usize = 32;

pub fn generate_cookie() -> Bytes {
    let cookie = thread_rng().gen::<[u8; COOKIE_LENGTH]>();

    Bytes::copy_from_slice(&cookie)
}
