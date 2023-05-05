use std::borrow::Borrow;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;

#[derive(Clone)]
pub struct PublicKey(Bytes);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let encoded = BASE64_STANDARD.encode(&self.0);

        f.write_str(&encoded)
    }
}

impl Borrow<[u8]> for PublicKey {
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl Deref for PublicKey {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PublicKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Bytes> for PublicKey {
    fn from(value: Bytes) -> Self {
        Self(value)
    }
}

impl From<PublicKey> for Bytes {
    fn from(value: PublicKey) -> Self {
        value.0
    }
}
