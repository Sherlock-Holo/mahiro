use std::io;

use bytes::Bytes;
use ring_io::buf::GBuf;

use crate::protocol::Frame;

pub enum Packet {
    Gbuf(GBuf),
    Bytes(Bytes),
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        match self {
            Packet::Gbuf(buf) => buf.as_slice(),
            Packet::Bytes(buf) => buf.as_ref(),
        }
    }
}

pub enum UdpMessage {
    Frame(Frame),
    Packet(io::Result<Packet>),
}

pub enum EncryptMessage {
    Init,
    Packet(Bytes),
    Frame(Frame),
    HandshakeTimeout,
    Heartbeat,
}

pub enum TunMessage {
    ToTun(Bytes),
}
