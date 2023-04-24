use core::mem::transmute;

use aya_bpf::bindings::__be32;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(transparent)]
pub struct Ipv4Addr {
    ip: [u8; 4],
}

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { ip: [a, b, c, d] }
    }

    pub fn eq_with_be32(&self, other: __be32) -> bool {
        self.ip == u32::from_be(other).to_be_bytes()
    }
}

impl From<__be32> for Ipv4Addr {
    fn from(value: __be32) -> Self {
        Self {
            ip: u32::from_be(value).to_be_bytes(),
        }
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from(value: [u8; 4]) -> Self {
        Self { ip: value }
    }
}

impl From<Ipv4Addr> for __be32 {
    fn from(value: Ipv4Addr) -> Self {
        u32::from_be_bytes(value.ip).to_be()
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(transparent)]
pub struct Ipv6Addr {
    ip: [u8; 16],
}

impl From<[u8; 16]> for Ipv6Addr {
    fn from(value: [u8; 16]) -> Self {
        Self { ip: value }
    }
}

impl From<Ipv6Addr> for [u8; 16] {
    fn from(value: Ipv6Addr) -> Self {
        value.ip
    }
}

impl From<Ipv6Addr> for [__be32; 4] {
    fn from(value: Ipv6Addr) -> Self {
        unsafe { transmute(value.ip) }
    }
}
