use bytes::{Bytes, BytesMut};
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

use crate::tun::Tun;

#[derive(Debug)]
pub struct TunActor {
    tun_device: Tun,
    packet_sender: Sender<Bytes>,
    packet_receiver: Receiver<Bytes>,
}

impl TunActor {
    async fn run_loop(&mut self) {
        let mut buf = BytesMut::with_capacity(4096);

        loop {
            self.run_circle(&mut buf).await;
        }
    }

    async fn run_circle(&mut self, buf: &mut BytesMut) {
        buf.clear();

        tokio::select! {
            result = self.tun_device.read_buf(buf) => {
                match result {
                    Err(err) => {
                        error!(%err, "receive packet failed");
                    }

                    Ok(_) => {
                        self.send_packet(Bytes::from(buf.to_vec())).await;
                    }
                }
            }

            packet = self.packet_receiver.next() => {
                match packet {
                    None => {
                        error!("packet receiver is closed");
                    }

                    Some(packet) => {
                        self.write_packet(&packet).await;
                    }
                }
            }
        }
    }

    async fn send_packet(&mut self, packet: Bytes) {
        if self.packet_sender.send(packet).await.is_err() {
            error!("send packet failed");
        } else {
            info!("send packet done");
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) {
        match self.tun_device.write(packet).await {
            Err(err) => {
                error!(%err, "write packet failed");
            }

            Ok(_) => {
                info!("write packet done");
            }
        }
    }
}
