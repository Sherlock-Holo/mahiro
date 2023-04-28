use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use ractor::concurrency::JoinHandle;
use ractor::factory::{
    FactoryMessage, Job, WorkerBuilder, WorkerId, WorkerMessage, WorkerStartContext,
};
use ractor::{Actor, ActorId, ActorProcessingErr, ActorRef};
use rtnetlink::Handle;
use tap::TapFallible;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tracing::error;

use crate::route_table::{RouteEntry, RouteTable};
use crate::tun::Tun;

use super::message::TunMessage as Message;

struct TunActor {
    worker_id: WorkerId,
    tun_ipv4: Ipv4Inet,
    tun_ipv6: Ipv6Inet,
    tun_name: String,
    netlink_handle: Handle,
    route_entries: Vec<RouteEntry>,
    fwmark: u32,
    encrypt: ActorRef<FactoryMessage<ActorId, Bytes>>,
}

struct TunActorBuilder {
    tun_ipv4: Ipv4Inet,
    tun_ipv6: Ipv6Inet,
    tun_name: String,
    netlink_handle: Handle,
    route_entries: Vec<RouteEntry>,
    fwmark: u32,
    encrypt: ActorRef<FactoryMessage<ActorId, Bytes>>,
}

impl WorkerBuilder<TunActor> for TunActorBuilder {
    fn build(&self, wid: WorkerId) -> TunActor {
        TunActor {
            worker_id: wid,
            tun_ipv4: self.tun_ipv4,
            tun_ipv6: self.tun_ipv6,
            tun_name: self.tun_name.clone(),
            netlink_handle: self.netlink_handle.clone(),
            route_entries: self.route_entries.clone(),
            fwmark: self.fwmark,
            encrypt: self.encrypt.clone(),
        }
    }
}

struct State {
    tun: WriteHalf<Tun>,
    route_table: RouteTable,
    read_task: JoinHandle<()>,
    factory: ActorRef<FactoryMessage<ActorId, Message>>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.read_task.abort();
    }
}

#[async_trait]
impl Actor for TunActor {
    type Msg = WorkerMessage<ActorId, Message>;
    type State = State;
    type Arguments = WorkerStartContext<ActorId, Message>;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let tun = Tun::new(
            self.tun_name.clone(),
            self.tun_ipv4,
            self.tun_ipv6,
            self.netlink_handle.clone(),
        )
        .await
        .tap_err(|err| error!(%err, "create tun failed"))?;

        let mut route_table = RouteTable::new(self.netlink_handle.clone());
        route_table.clean_route_tables(self.fwmark).await?;
        route_table
            .update_route(self.fwmark, &self.route_entries)
            .await?;

        let (mut read_tun, write_tun) = io::split(tun);
        let read_task = tokio::spawn(async move {
            let mut buf = BytesMut::with_capacity(65535);
            let id = myself.get_id();
            loop {
                buf.clear();

                match read_tun
                    .read_buf(&mut buf)
                    .await
                    .map(|n| buf.copy_to_bytes(n))
                {
                    Err(err) => {
                        error!(%err, "read packet from tun failed");

                        let _ = myself.send_message(WorkerMessage::Dispatch(Job {
                            key: id,
                            msg: Message::FromTun(Err(err)),
                            options: Default::default(),
                        }));

                        return;
                    }

                    Ok(data) => {
                        if let Err(err) = myself.send_message(WorkerMessage::Dispatch(Job {
                            key: id,
                            msg: Message::FromTun(Ok(data)),
                            options: Default::default(),
                        })) {
                            error!(%err, "send packet failed");

                            return;
                        }
                    }
                }
            }
        });

        Ok(State {
            tun: write_tun,
            route_table,
            read_task,
            factory: args.factory,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let message = match message {
            WorkerMessage::FactoryPing(ping) => {
                state
                    .factory
                    .send_message(FactoryMessage::WorkerPong(self.worker_id, ping))?;

                return Ok(());
            }
            WorkerMessage::Dispatch(message) => message,
        };

        match message.msg {
            Message::FromTun(Err(err)) => {
                error!(%err, "read packet from tun failed");

                return Err(err.into());
            }

            Message::FromTun(Ok(packet)) => {
                let id = self.encrypt.get_id();
                self.encrypt
                    .send_message(FactoryMessage::Dispatch(Job {
                        key: id,
                        msg: packet,
                        options: Default::default(),
                    }))
                    .tap_err(|err| error!(%err, "send packet to encrypt failed"))?;

                state.factory.send_message(FactoryMessage::Finished(
                    self.worker_id,
                    state.factory.get_id(),
                ))?;

                Ok(())
            }

            Message::ToTun(packet) => {
                state
                    .tun
                    .write(&packet)
                    .await
                    .tap_err(|err| error!(%err, "write packet to tun failed"))?;

                state.factory.send_message(FactoryMessage::Finished(
                    self.worker_id,
                    state.factory.get_id(),
                ))?;

                Ok(())
            }
        }
    }
}
