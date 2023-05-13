use std::collections::HashMap;
use std::fmt::Debug;
use std::future;
use std::io::ErrorKind;
use std::net::IpAddr;

use futures_util::TryStreamExt;
use netlink_packet_route::route::Nla as RouteNla;
use netlink_packet_route::rule::Nla;
use netlink_packet_route::{
    RuleMessage, AF_INET, AF_INET6, FR_ACT_TO_TBL, RTN_THROW, RT_TABLE_COMPAT,
};
use rtnetlink::{Handle, IpVersion, LinkHandle, RouteHandle, RuleHandle};
use tap::TapFallible;
use tracing::{error, info, instrument};

const TABLE_ID: u32 = 25;

pub struct RouteTable {
    route_handle: RouteHandle,
    rule_handle: RuleHandle,
    link_handle: LinkHandle,
}

impl RouteTable {
    pub fn new(netlink_handle: Handle) -> Self {
        Self {
            route_handle: netlink_handle.route(),
            rule_handle: netlink_handle.rule(),
            link_handle: netlink_handle.link(),
        }
    }

    #[instrument(skip(self), err)]
    pub async fn clean(&self) -> anyhow::Result<()> {
        for ip_version in [IpVersion::V4, IpVersion::V6] {
            self.flush_route(TABLE_ID, ip_version.clone()).await?;

            info!(TABLE_ID, ?ip_version, "flush table done");

            let mut rule_message = RuleMessage::default();
            rule_message.header.family = match ip_version {
                IpVersion::V4 => AF_INET as _,
                IpVersion::V6 => AF_INET6 as _,
            };
            rule_message.header.table = RT_TABLE_COMPAT;
            rule_message.nlas = vec![Nla::Table(TABLE_ID as _)];

            match self.rule_handle.del(rule_message).execute().await {
                Err(rtnetlink::Error::NetlinkError(err_msg))
                    if err_msg.to_io().kind() == ErrorKind::NotFound =>
                {
                    info!("a route rule not exists, ignore it");

                    continue;
                }

                Err(err) => {
                    error!(%err, TABLE_ID, ?ip_version, "delete route rule failed");

                    return Err(err.into());
                }

                Ok(_) => {
                    info!(TABLE_ID, ?ip_version, "delete route rule done");
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self), err)]
    pub async fn set_route(&mut self, route_entries: &[RouteEntry]) -> anyhow::Result<()> {
        self.add_route_entries(route_entries).await?;
        self.add_route_rule().await?;

        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn add_route_entries(&mut self, new_route_entries: &[RouteEntry]) -> anyhow::Result<()> {
        let mut iface_index_cache = HashMap::new();
        for route_entry in new_route_entries {
            let mut add_request = self.route_handle.add().table(RT_TABLE_COMPAT);
            add_request
                .message_mut()
                .nlas
                .push(RouteNla::Table(TABLE_ID));

            match &route_entry.action {
                RouteEntryAction::Throw => {
                    add_request = add_request.kind(RTN_THROW);
                }

                RouteEntryAction::OutIface(iface) => {
                    let index = match iface_index_cache.get(iface) {
                        None => {
                            let index = self.get_iface_index(iface).await?;

                            iface_index_cache.insert(iface, index);

                            index
                        }

                        Some(&index) => index,
                    };

                    add_request = add_request.output_interface(index);
                }
            }

            match route_entry.addr {
                IpAddr::V4(addr) => {
                    add_request
                        .v4()
                        .destination_prefix(addr, route_entry.prefix)
                        .execute().await.tap_err(|err| {
                        error!(%err, %addr, prefix = %route_entry.prefix, "add route entry failed");
                    })?;
                }

                IpAddr::V6(addr) => {
                    add_request
                        .v6()
                        .destination_prefix(addr, route_entry.prefix)
                        .execute().await.tap_err(|err| {
                        error!(%err, %addr, prefix = %route_entry.prefix, "add route entry failed");
                    })?;
                }
            }
        }

        Ok(())
    }

    async fn add_route_rule(&mut self) -> anyhow::Result<()> {
        let mut rule_add_request = self.rule_handle.add().v4().table(RT_TABLE_COMPAT);
        rule_add_request
            .message_mut()
            .nlas
            .push(Nla::Table(TABLE_ID));

        rule_add_request
            .action(FR_ACT_TO_TBL)
            .execute()
            .await
            .tap_err(|err| error!(%err, "add ipv4 route rule failed"))?;

        let mut rule_add_request = self.rule_handle.add().v6().table(RT_TABLE_COMPAT);
        rule_add_request
            .message_mut()
            .nlas
            .push(Nla::Table(TABLE_ID));

        rule_add_request
            .action(FR_ACT_TO_TBL)
            .execute()
            .await
            .tap_err(|err| error!(%err, "add ipv6 route rule failed"))?;

        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn flush_route(&self, table: u32, ip_version: IpVersion) -> anyhow::Result<()> {
        let get_request = self.route_handle.get(ip_version.clone());

        let route_entries = get_request
            .execute()
            .try_filter(|route_entry| {
                if route_entry.header.table == table as _ {
                    future::ready(true)
                } else {
                    let result = route_entry.header.table == RT_TABLE_COMPAT
                        && route_entry.nlas.contains(&RouteNla::Table(table as _));

                    future::ready(result)
                }
            })
            .try_collect::<Vec<_>>()
            .await
            .tap_err(|err| error!(%err, ?ip_version, table, "collect table entry failed"))?;

        info!(
            table,
            ?ip_version,
            ?route_entries,
            "collect table rule done"
        );

        for route_entry in route_entries {
            self.route_handle
                .del(route_entry)
                .execute()
                .await
                .tap_err(|err| error!(%err, table, ?ip_version, "delete route entry failed"))?;
        }

        Ok(())
    }

    async fn get_iface_index(&mut self, iface: &str) -> anyhow::Result<u32> {
        let out_iface_index = self
            .link_handle
            .get()
            .match_name(iface.to_string())
            .execute()
            .try_next()
            .await
            .tap_err(|err| {
                error!(%err, iface, "get iface index failed");
            })?
            .ok_or_else(|| anyhow::anyhow!("iface {} not exists", iface))?;

        Ok(out_iface_index.header.index)
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct RouteEntry {
    pub prefix: u8,
    pub addr: IpAddr,
    pub action: RouteEntryAction,
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum RouteEntryAction {
    Throw,
    OutIface(String),
}
