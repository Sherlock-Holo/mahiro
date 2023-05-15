use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use cidr::{Ipv4Inet, Ipv6Inet};
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::task::noop_waker_ref;
use futures_util::{SinkExt, StreamExt};
use rtnetlink::Handle;
use tap::TapFallible;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, warn};

use super::message::EncryptMessage;
use super::message::TunMessage as Message;
use super::peer_store::PeerStore;
use crate::ip_packet;
use crate::ip_packet::IpLocation;
use crate::tun::Tun;

#[derive(Debug)]
pub struct TunActor {
    mailbox_sender: Sender<Message>,
    mailbox: Receiver<Message>,
    peer_store: PeerStore,

    tun: WriteHalf<Tun>,
    read_task: JoinHandle<()>,

    tun_ipv4: Ipv4Inet,
    tun_ipv6: Ipv6Inet,
    tun_name: String,
    netlink_handle: Handle,
}

impl TunActor {
    pub async fn new(
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        peer_store: PeerStore,
        tun_ipv4: Ipv4Inet,
        tun_ipv6: Ipv6Inet,
        tun_name: String,
        netlink_handle: Handle,
    ) -> anyhow::Result<Self> {
        let (tun, read_task) = Self::start(
            mailbox_sender.clone(),
            tun_ipv4,
            tun_ipv6,
            tun_name.clone(),
            netlink_handle.clone(),
        )
        .await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            peer_store,
            tun,
            read_task,
            tun_ipv4,
            tun_ipv6,
            tun_name,
            netlink_handle,
        })
    }

    #[instrument(err)]
    async fn start(
        mailbox_sender: Sender<Message>,
        tun_ipv4: Ipv4Inet,
        tun_ipv6: Ipv6Inet,
        tun_name: String,
        netlink_handle: Handle,
    ) -> anyhow::Result<(WriteHalf<Tun>, JoinHandle<()>)> {
        let tun = Tun::new(tun_name, tun_ipv4, tun_ipv6, netlink_handle)
            .await
            .tap_err(|err| error!(%err, "create tun failed"))?;
        let (tun_read, tun_write) = io::split(tun);

        let task = tokio::spawn(Self::read_from_tun(tun_read, mailbox_sender));

        Ok((tun_write, task))
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        self.read_task.abort();
        let _ = self.tun.shutdown().await;

        let (tun, read_task) = Self::start(
            self.mailbox_sender.clone(),
            self.tun_ipv4,
            self.tun_ipv6,
            self.tun_name.clone(),
            self.netlink_handle.clone(),
        )
        .await?;

        self.tun = tun;
        self.read_task = read_task;

        Ok(())
    }

    async fn read_from_tun(mut tun_read: ReadHalf<Tun>, mut sender: Sender<Message>) {
        let mut buf = BytesMut::with_capacity(1500 * 5);
        loop {
            buf.reserve(1500);

            let packet = match tun_read.read_buf(&mut buf).await {
                Err(err) => {
                    error!(%err, "receive tun packet failed");

                    let _ = sender.send(Message::FromTun(Err(err))).await;

                    return;
                }

                Ok(_) => buf.split().freeze(),
            };

            if let Err(err) = sender.send(Message::FromTun(Ok(packet))).await {
                error!(%err, "send tun packet failed");

                return;
            }
        }
    }

    pub async fn run(&mut self) {
        loop {
            if let Err(err) = self.run_circle().await {
                error!(%err, "tun run circle failed, need restart");

                loop {
                    match self.restart().await {
                        Err(err) => {
                            error!(%err, "tun restart failed");
                        }

                        Ok(_) => {
                            info!("tun restart done");

                            break;
                        }
                    }
                }
            }
        }
    }

    #[instrument(err)]
    async fn run_circle(&mut self) -> anyhow::Result<()> {
        let message = match self.mailbox.next().await {
            None => {
                error!("receive message from mailbox failed");

                return Err(anyhow::anyhow!("receive message from mailbox failed"));
            }

            Some(message) => message,
        };

        match message {
            Message::FromTun(Err(err)) => {
                error!(%err, "read packet from tun failed");

                Err(err.into())
            }

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

                match Pin::new(&mut self.tun)
                    .poll_write(&mut Context::from_waker(noop_waker_ref()), &packet)
                {
                    Poll::Pending => {
                        warn!("tun queue is full, drop packet");

                        Ok(())
                    }

                    Poll::Ready(result) => {
                        result.tap_err(|err| error!(%err, "write packet to tun failed"))?;

                        debug!(%src_ip, %dst_ip, "write packet to tun done");

                        Ok(())
                    }
                }
            }

            Message::FromTun(Ok(packet)) => {
                match ip_packet::get_packet_ip(&packet, IpLocation::Dst) {
                    None => {
                        error!("packet from tun doesn't have ip addr, drop it");

                        Ok(())
                    }

                    Some(ip) => {
                        debug!(%ip, "get tun packet dst ip done");

                        if let IpAddr::V6(ip) = ip {
                            if ip.is_unicast_link_local() {
                                debug!(%ip, "ip is ipv6 link local, drop it");

                                return Ok(());
                            }
                        }

                        let mut sender = match self.peer_store.get_sender_by_mahiro_ip(ip) {
                            None => {
                                debug!(%ip, "ip doesn't in connected peers, maybe peer is disconnected, drop it");

                                return Ok(());
                            }

                            Some(sender) => sender,
                        };

                        if let Err(err) = sender.send(EncryptMessage::Packet(packet)).await {
                            error!(%err, %ip, "send tun packet to encrypt actor failed");
                        }

                        Ok(())
                    }
                }
            }
        }
    }
}
