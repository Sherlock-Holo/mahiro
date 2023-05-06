use bytes::{Buf, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use rtnetlink::Handle;
use tap::TapFallible;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tracing::{error, info};

use super::message::TunMessage as Message;
use crate::mahiro::message::EncryptMessage;
use crate::route_table::{RouteEntry, RouteTable};
use crate::tun::Tun;

#[derive(Debug)]
pub struct TunConfig {
    pub tun_ipv4: Ipv4Inet,
    pub tun_ipv6: Ipv6Inet,
    pub tun_name: String,
    pub netlink_handle: Handle,
    pub route_entries: Vec<RouteEntry>,
}

#[derive(Debug)]
pub struct TunActor {
    mailbox_sender: Sender<Message>,
    mailbox: Receiver<Message>,
    encrypt_sender: Sender<EncryptMessage>,

    tun_config: TunConfig,

    tun: WriteHalf<Tun>,
    route_table: RouteTable,
    read_task: JoinHandle<()>,
}

impl TunActor {
    pub async fn new(
        encrypt_sender: Sender<EncryptMessage>,
        mailbox_sender: Sender<Message>,
        mailbox: Receiver<Message>,
        tun_config: TunConfig,
    ) -> anyhow::Result<Self> {
        let (tun, route_table, read_task) =
            Self::start(mailbox_sender.clone(), &tun_config).await?;

        Ok(Self {
            mailbox_sender,
            mailbox,
            encrypt_sender,
            tun_config,
            tun,
            route_table,
            read_task,
        })
    }

    async fn start(
        mailbox_sender: Sender<Message>,
        tun_config: &TunConfig,
    ) -> anyhow::Result<(WriteHalf<Tun>, RouteTable, JoinHandle<()>)> {
        let tun = Tun::new(
            tun_config.tun_name.clone(),
            tun_config.tun_ipv4,
            tun_config.tun_ipv6,
            tun_config.netlink_handle.clone(),
        )
        .await
        .tap_err(|err| error!(%err, "create tun failed"))?;

        info!(?tun, "create tun done");

        let mut route_table = RouteTable::new(tun_config.netlink_handle.clone());

        route_table.clean_route_tables().await?;

        info!("clean route tables done");

        route_table.update_route(&tun_config.route_entries).await?;

        info!(route_entries = ?tun_config.route_entries, "update route done");

        let (tun_read, tun_write) = io::split(tun);

        let read_task =
            tokio::spawn(async move { Self::read_from_tun(tun_read, mailbox_sender).await });

        Ok((tun_write, route_table, read_task))
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        self.read_task.abort();
        self.tun
            .shutdown()
            .await
            .tap_err(|err| error!(%err, "shutdown tun failed"))?;

        let (tun, route_table, read_task) =
            Self::start(self.mailbox_sender.clone(), &self.tun_config).await?;

        self.tun = tun;
        self.route_table = route_table;
        self.read_task = read_task;

        Ok(())
    }

    async fn read_from_tun(mut tun_read: ReadHalf<Tun>, mut sender: Sender<Message>) {
        let mut buf = BytesMut::with_capacity(4096);
        loop {
            buf.clear();

            let packet = match tun_read.read_buf(&mut buf).await {
                Err(err) => {
                    error!(%err, "receive tun packet failed");

                    let _ = sender.send(Message::FromTun(Err(err))).await;

                    return;
                }

                Ok(n) => buf.copy_to_bytes(n),
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

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        let message = match self.mailbox.next().await {
            None => {
                error!("receive packet from mailbox failed");

                return Err(anyhow::anyhow!("receive packet from mailbox failed"));
            }

            Some(message) => message,
        };

        match message {
            Message::FromTun(Err(err)) => {
                error!(%err, "read packet from tun failed");

                Err(err.into())
            }

            Message::FromTun(Ok(packet)) => {
                self.encrypt_sender
                    .send(EncryptMessage::Packet(packet))
                    .await
                    .tap_err(|err| error!(%err, "send packet to encrypt failed"))?;

                info!("send packet to encrypt done");

                Ok(())
            }

            Message::ToTun(packet) => {
                self.tun
                    .write(&packet)
                    .await
                    .tap_err(|err| error!(%err, "write packet to tun failed"))?;

                info!("write packet to tun done");

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

    use futures_channel::mpsc;
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
            tun_ipv4: Ipv4Inet::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap(),
            tun_ipv6: Ipv6Inet::new(Ipv6Addr::from_str("fc00:100::1").unwrap(), 64).unwrap(),
            tun_name: "test_tun".to_string(),
            netlink_handle: handle,
            route_entries: vec![],
        };

        let (mailbox_sender, mailbox) = mpsc::channel(10);
        let (encrypt_sender, mut encrypt_mailbox) = mpsc::channel(10);
        let mut tun_actor =
            TunActor::new(encrypt_sender, mailbox_sender.clone(), mailbox, tun_config)
                .await
                .unwrap();

        tokio::spawn(async move { tun_actor.run().await });

        // time::sleep(Duration::from_secs(3600)).await;

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
