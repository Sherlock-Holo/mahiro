use bytes::BytesMut;
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::StreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use rtnetlink::Handle;
use tap::TapFallible;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use super::message::TunMessage as Message;
use crate::ip_packet;
use crate::ip_packet::IpLocation;
use crate::mahiro::message::EncryptMessage;
use crate::tun::{Tun, TunReader, TunWriter};
use crate::util::Receiver;

#[derive(Debug)]
pub struct TunConfig {
    pub tun_ipv4: Ipv4Net,
    pub tun_ipv6: Ipv6Net,
    pub tun_name: String,
    pub netlink_handle: Handle,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct TunActor {
    mailbox_sender: Sender<Message>,
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    encrypt_sender: Sender<EncryptMessage>,

    tun_config: TunConfig,

    tun_writers: Vec<TunWriter>,
    tun_readers: Vec<TunReader>,
}

impl TunActor {
    pub async fn new(
        encrypt_sender: Sender<EncryptMessage>,
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        tun_config: TunConfig,
    ) -> anyhow::Result<Self> {
        let (tun_writers, tun_readers) = Self::start(&tun_config).await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            encrypt_sender,
            tun_config,
            tun_writers,
            tun_readers,
        })
    }

    async fn start(tun_config: &TunConfig) -> anyhow::Result<(Vec<TunWriter>, Vec<TunReader>)> {
        let tun = Tun::new(
            tun_config.tun_name.clone(),
            tun_config.tun_ipv4,
            tun_config.tun_ipv6,
            tun_config.netlink_handle.clone(),
        )
        .await
        .tap_err(|err| error!(%err, "create tun failed"))?;

        info!(?tun, "create tun done");

        let (tun_readers, tun_writers) = tun.split_queues();

        Ok((tun_writers, tun_readers))
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        let (tun_writers, tun_readers) = Self::start(&self.tun_config).await?;

        self.tun_writers = tun_writers;
        self.tun_readers = tun_readers;

        Ok(())
    }

    async fn read_from_tun(
        mut tun_reader: TunReader,
        encrypt_sender: Sender<EncryptMessage>,
    ) -> anyhow::Result<()> {
        let mut buf = BytesMut::with_capacity(1500 * 5);
        loop {
            buf.reserve(1500);

            let packet = match tun_reader.read_buf(&mut buf).await {
                Err(err) => {
                    error!(%err, "receive tun packet failed");

                    return Err(err.into());
                }

                Ok(_) => buf.split().freeze(),
            };

            let dst_ip = match ip_packet::get_packet_ip(&packet, IpLocation::Dst) {
                None => {
                    debug!("drop no dst ip packet");

                    continue;
                }

                Some(ip) => ip,
            };

            let src_ip = match ip_packet::get_packet_ip(&packet, IpLocation::Src) {
                None => {
                    debug!("drop no src ip packet");

                    continue;
                }

                Some(ip) => ip,
            };

            match encrypt_sender.try_send(EncryptMessage::Packet(packet)) {
                Err(TrySendError::Full(_)) => {
                    warn!("encrypt actor mailbox is full");
                }

                Err(err) => {
                    return Err(err.into());
                }

                Ok(_) => {
                    debug!(%src_ip, %dst_ip, "send packet to encrypt done");
                }
            }
        }
    }

    pub async fn run(&mut self) {
        let mut join_set = JoinSet::new();
        loop {
            let count = self.tun_writers.len();
            for tun_writer in self.tun_writers.drain(..) {
                let mut tun_actor_queue_writer = TunActorQueueWriter {
                    mailbox: self.mailbox.clone(),
                    tun_writer,
                };

                join_set.spawn(async move { tun_actor_queue_writer.run().await });
            }

            for tun_reader in self.tun_readers.drain(..) {
                let encrypt_sender = self.encrypt_sender.clone();

                join_set.spawn(Self::read_from_tun(tun_reader, encrypt_sender));
            }

            info!("start {count} tun actor queue writer done");

            while let Some(result) = join_set.join_next().await {
                if let Err(err) = result.unwrap() {
                    error!(%err, "tun actor queue writer stop with error");

                    break;
                }
            }

            join_set.shutdown().await;

            error!("tun actor queue writer stop, need restart");

            loop {
                match self.restart().await {
                    Err(err) => {
                        error!(%err, "tun actor restart failed");
                    }

                    Ok(_) => {
                        info!("tun actor restart done");

                        break;
                    }
                }
            }
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
struct TunActorQueueWriter {
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    tun_writer: TunWriter,
}

impl TunActorQueueWriter {
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.run_circle().await?;
        }
    }

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        let message = match self.mailbox.next().await {
            None => {
                error!("receive packet from mailbox failed");

                return Err(anyhow::anyhow!("receive packet from mailbox failed"));
            }

            Some(message) => message,
        };

        match message {
            Message::ToTun(packet) => {
                self.tun_writer
                    .write(&packet)
                    .await
                    .tap_err(|err| error!(%err, "write packet to tun failed"))?;

                debug!("write packet to tun done");

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use network_types::ip::{IpProto, Ipv4Hdr};
    use network_types::udp::UdpHdr;
    use nix::unistd::getuid;
    use test_log::test;
    use tokio::net::UdpSocket;
    use tracing::warn;

    use super::*;

    #[test(tokio::test)]
    async fn test() {
        if !getuid().is_root() {
            warn!("ignore tun test when is not root");

            return;
        }

        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let tun_config = TunConfig {
            tun_ipv4: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap(),
            tun_ipv6: Ipv6Net::new(Ipv6Addr::from_str("fc00:100::1").unwrap(), 64).unwrap(),
            tun_name: "test_tun".to_string(),
            netlink_handle: handle,
        };

        let (mailbox_sender, mailbox) = flume::bounded(10);
        let (encrypt_sender, encrypt_mailbox) = flume::bounded(10);
        let mut tun_actor = TunActor::new(
            encrypt_sender,
            mailbox_sender.clone(),
            mailbox.into_stream(),
            tun_config,
        )
        .await
        .unwrap();

        tokio::spawn(async move { tun_actor.run().await });

        let mut encrypt_mailbox = encrypt_mailbox.into_stream();

        let udp_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        udp_socket.connect("192.168.1.2:8888").await.unwrap();
        udp_socket.send(b"test").await.unwrap();

        loop {
            let encrypt_message = encrypt_mailbox.next().await.unwrap();
            let packet = match encrypt_message {
                EncryptMessage::Packet(packet) => packet,
                _ => panic!("other encrypt message"),
            };
            let first = packet[0];
            if (first >> 4) != 0b100 {
                continue;
            }

            // safety: the packet is an ipv4 packet
            let ipv4_hdr = unsafe { &*(packet.as_ptr() as *const Ipv4Hdr) };
            if Ipv4Addr::from(u32::from_be(ipv4_hdr.dst_addr)) != Ipv4Addr::new(192, 168, 1, 2) {
                continue;
            }

            if ipv4_hdr.proto != IpProto::Udp {
                continue;
            }

            let udp_hdr = unsafe { &*(packet.as_ptr().add(size_of::<Ipv4Hdr>()) as *const UdpHdr) };
            if u16::from_be(udp_hdr.dest) != 8888 {
                continue;
            }

            return;
        }
    }
}
