use bytes::Bytes;

pub enum TunMessage {
    ToTun(Bytes),
}

pub enum Http2Message {
    Packet(Bytes),
}
