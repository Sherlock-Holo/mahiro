use bytes::{Buf, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures_channel::mpsc;
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use rtnetlink::Handle;
use tap::TapFallible;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::mahiro::message::EncryptMessage;
use crate::route_table::{RouteEntry, RouteTable};
use crate::tun::Tun;

use super::message::TunMessage as Message;

#[derive(Debug)]
struct TunConfig {
    tun_ipv4: Ipv4Inet,
    tun_ipv6: Ipv6Inet,
    tun_name: String,
    netlink_handle: Handle,
    route_entries: Vec<RouteEntry>,
    fwmark: u32,
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
        tun_ipv4: Ipv4Inet,
        tun_ipv6: Ipv6Inet,
        tun_name: String,
        netlink_handle: Handle,
        route_entries: Vec<RouteEntry>,
        fwmark: u32,
    ) -> anyhow::Result<(Self, Sender<Message>)> {
        let tun_config = TunConfig {
            tun_ipv4,
            tun_ipv6,
            tun_name,
            netlink_handle,
            route_entries,
            fwmark,
        };

        let (sender, mailbox) = mpsc::channel(10);

        let (tun, route_table, read_task) = Self::start(sender.clone(), &tun_config).await?;

        Ok((
            Self {
                mailbox_sender: sender.clone(),
                mailbox,
                encrypt_sender,
                tun_config,
                tun,
                route_table,
                read_task,
            },
            sender,
        ))
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

        let fwmark = tun_config.fwmark;

        route_table.clean_route_tables(fwmark).await?;

        info!(fwmark, "clean route tables done");

        route_table
            .update_route(fwmark, &tun_config.route_entries)
            .await?;

        info!(fwmark, route_entries = ?tun_config.route_entries, "update route done");

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
