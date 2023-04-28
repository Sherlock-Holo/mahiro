use std::io;

use bytes::Bytes;

use crate::protocol::Frame;

pub enum UdpMessage {
    Frame(Frame),
    Packet(io::Result<Bytes>),
}

pub enum EncryptMessage {
    Init,
    Packet(Bytes),
    Frame(Frame),
    HandshakeTimeout,
    Heartbeat,
}

pub enum TunMessage {
    FromTun(io::Result<Bytes>),
    ToTun(Bytes),
}
