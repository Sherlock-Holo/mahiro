use bytes::Bytes;

pub enum TunMessage {
    ToTun(Bytes),
}

pub enum TransportMessage {
    Packet(Bytes),
}
