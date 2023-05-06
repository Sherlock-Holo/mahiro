use std::mem::transmute;
use std::net::{Ipv4Addr, Ipv6Addr};

use aya::Pod;

pub type Be32 = u32;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(transparent)]
pub struct BpfIpv4Addr {
    ip: [u8; 4],
}

unsafe impl Pod for BpfIpv4Addr {}

impl BpfIpv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { ip: [a, b, c, d] }
    }

    pub fn eq_with_be32(&self, other: Be32) -> bool {
        self.ip == u32::from_be(other).to_be_bytes()
    }
}

impl From<Ipv4Addr> for BpfIpv4Addr {
    fn from(value: Ipv4Addr) -> Self {
        value.octets().into()
    }
}

impl From<Be32> for BpfIpv4Addr {
    fn from(value: Be32) -> Self {
        Self {
            ip: u32::from_be(value).to_be_bytes(),
        }
    }
}

impl From<[u8; 4]> for BpfIpv4Addr {
    fn from(value: [u8; 4]) -> Self {
        Self { ip: value }
    }
}

impl From<BpfIpv4Addr> for Be32 {
    fn from(value: BpfIpv4Addr) -> Self {
        u32::from_be_bytes(value.ip).to_be()
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(transparent)]
pub struct BpfIpv6Addr {
    ip: [u8; 16],
}

unsafe impl Pod for BpfIpv6Addr {}

impl From<Ipv6Addr> for BpfIpv6Addr {
    fn from(value: Ipv6Addr) -> Self {
        value.octets().into()
    }
}

impl From<[u8; 16]> for BpfIpv6Addr {
    fn from(value: [u8; 16]) -> Self {
        Self { ip: value }
    }
}

impl From<BpfIpv6Addr> for [u8; 16] {
    fn from(value: BpfIpv6Addr) -> Self {
        value.ip
    }
}

impl From<BpfIpv6Addr> for [Be32; 4] {
    fn from(value: BpfIpv6Addr) -> Self {
        unsafe { transmute(value.ip) }
    }
}
