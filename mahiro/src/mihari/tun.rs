use std::net::IpAddr;

use bytes::BytesMut;
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::StreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use rtnetlink::Handle;
use tap::TapFallible;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tracing::{debug, error, info, instrument, warn};

use super::message::Http2Message;
use super::message::TunMessage as Message;
use super::peer_store::PeerStore;
use crate::ip_packet;
use crate::ip_packet::IpLocation;
use crate::tun::{Tun, TunReader, TunWriter};
use crate::util::Receiver;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct TunActor {
    mailbox_sender: Sender<Message>,
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    peer_store: PeerStore,

    tun_ipv4: Ipv4Net,
    tun_ipv6: Ipv6Net,
    tun_name: String,
    netlink_handle: Handle,

    tun_writers: Vec<TunWriter>,
    tun_readers: Vec<TunReader>,
}

impl TunActor {
    pub async fn new(
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        peer_store: PeerStore,
        tun_ipv4: Ipv4Net,
        tun_ipv6: Ipv6Net,
        tun_name: String,
        netlink_handle: Handle,
    ) -> anyhow::Result<Self> {
        let (tun_writers, tun_readers) =
            Self::start(tun_ipv4, tun_ipv6, tun_name.clone(), netlink_handle.clone()).await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            peer_store,
            tun_ipv4,
            tun_ipv6,
            tun_name,
            netlink_handle,
            tun_writers,
            tun_readers,
        })
    }

    #[instrument(err)]
    async fn start(
        tun_ipv4: Ipv4Net,
        tun_ipv6: Ipv6Net,
        tun_name: String,
        netlink_handle: Handle,
    ) -> anyhow::Result<(Vec<TunWriter>, Vec<TunReader>)> {
        let tun = Tun::new(tun_name, tun_ipv4, tun_ipv6, netlink_handle)
            .await
            .tap_err(|err| error!(%err, "create tun failed"))?;

        info!(?tun, "create tun done");

        let (tun_readers, tun_writers) = tun.split_queues();

        Ok((tun_writers, tun_readers))
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        let (tun_writers, tun_readers) = Self::start(
            self.tun_ipv4,
            self.tun_ipv6,
            self.tun_name.clone(),
            self.netlink_handle.clone(),
        )
        .await?;

        self.tun_writers = tun_writers;
        self.tun_readers = tun_readers;

        Ok(())
    }

    async fn read_from_tun(mut tun_reader: TunReader, peer_store: PeerStore) -> anyhow::Result<()> {
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

            match ip_packet::get_packet_ip(&packet, IpLocation::Dst) {
                None => {
                    error!("packet from tun doesn't have ip addr, drop it");

                    continue;
                }

                Some(ip) => {
                    debug!(%ip, "get tun packet dst ip done");

                    if let IpAddr::V6(ip) = ip {
                        if ip.is_unicast_link_local() {
                            debug!(%ip, "ip is ipv6 link local, drop it");

                            continue;
                        }
                    }

                    let sender = match peer_store.get_http2_transport_sender_by_mahiro_ip(ip) {
                        None => {
                            debug!(%ip, "ip doesn't in connected peers, maybe peer is disconnected, drop it");

                            continue;
                        }

                        Some(sender) => sender,
                    };

                    match sender.try_send(Http2Message::Packet(packet)) {
                        Err(TrySendError::Full(_)) => {
                            warn!("encrypt actor mailbox is full");
                        }

                        Err(err) => {
                            error!(%err, %ip, "send tun packet to encrypt actor failed");
                        }

                        Ok(_) => {}
                    }
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
                join_set.spawn(Self::read_from_tun(tun_reader, self.peer_store.clone()));
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
                let dst_ip = match ip_packet::get_packet_ip(&packet, IpLocation::Dst) {
                    None => {
                        debug!("drop no dst ip packet");

                        return Ok(());
                    }

                    Some(ip) => ip,
                };

                let src_ip = match ip_packet::get_packet_ip(&packet, IpLocation::Src) {
                    None => {
                        debug!("drop no src ip packet");

                        return Ok(());
                    }

                    Some(ip) => ip,
                };

                self.tun_writer
                    .write(&packet)
                    .await
                    .tap_err(|err| error!(%err, "write packet to tun failed"))?;

                debug!(%src_ip, %dst_ip, "write packet to tun done");

                Ok(())
            }
        }
    }
}
