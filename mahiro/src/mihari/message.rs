use std::io;
use std::net::SocketAddr;

use bytes::Bytes;

use crate::protocol::Frame;

pub enum EncryptMessage {
    Packet(Bytes),
    Frame { frame: Frame, from: SocketAddr },
    HandshakeTimeout,
    Heartbeat,
}

pub enum UdpMessage {
    Frame { frame: Frame, to: SocketAddr },
    Packet(io::Result<(Bytes, SocketAddr)>),
}

pub enum TunMessage {
    FromTun(io::Result<Bytes>),
    ToTun(Bytes),
}
