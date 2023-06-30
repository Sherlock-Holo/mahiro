use std::io;
use std::mem::size_of;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Default)]
pub struct QuicStreamDecoder {
    len: Option<u16>,
}

impl Decoder for QuicStreamDecoder {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.len {
                None => {
                    if src.len() < 2 {
                        return Ok(None);
                    }

                    let len = src.get_u16();
                    self.len = Some(len);
                }

                Some(len) => {
                    if src.len() < len as _ {
                        src.reserve(len as _);

                        return Ok(None);
                    }

                    self.len.take();

                    return Ok(Some(src.split_to(len as _).freeze()));
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct QuicStreamEncoder {}

impl Encoder<Bytes> for QuicStreamEncoder {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(size_of::<u16>() + item.len());
        dst.put_u16(item.len() as _);
        dst.put(item);

        Ok(())
    }
}
