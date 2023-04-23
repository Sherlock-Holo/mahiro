pub mod ipv4;
pub mod ipv6;

const MAX_CONNTRACK_TABLE_SIZE: u32 = 65535;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    InsertConntrackError,
    RemoveConntrackError,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ConntrackType {
    Snat,
    Dnat,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProtocolType {
    Tcp = 0,
    Udp = 1,
}
