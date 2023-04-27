use std::fmt::{Debug, Formatter};
use std::net::IpAddr;

use futures_util::TryStreamExt;
use netlink_packet_route::rule::Nla;
use netlink_packet_route::{RuleMessage, AF_INET, AF_INET6};
use rtnetlink::{Handle, IpVersion, LinkHandle, RouteHandle, RuleHandle};
use tap::TapFallible;
use tracing::{error, info, instrument};

const TABLE_ID1: u8 = 25;
const TABLE_ID2: u8 = 24;

pub struct RouteTable {
    current_table_id: u8,
    route_handle: RouteHandle,
    rule_handle: RuleHandle,
    link_handle: LinkHandle,
}

impl Debug for RouteTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteTable")
            .field("current_table_id", &self.current_table_id)
            .finish_non_exhaustive()
    }
}

impl RouteTable {
    pub fn new(netlink_handle: Handle) -> Self {
        Self {
            // make sure first update use table id 1
            current_table_id: TABLE_ID2,
            route_handle: netlink_handle.route(),
            rule_handle: netlink_handle.rule(),
            link_handle: netlink_handle.link(),
        }
    }

    #[instrument(err)]
    pub async fn clean_route_tables(&self, fwmark: u32) -> anyhow::Result<()> {
        for table in [TABLE_ID1, TABLE_ID2] {
            for ip_version in [IpVersion::V4, IpVersion::V6] {
                self.flush_route(table, ip_version.clone()).await?;

                info!(table, ?ip_version, "flush table done");

                let mut rule_message = RuleMessage::default();
                rule_message.header.family = match ip_version {
                    IpVersion::V4 => AF_INET as _,
                    IpVersion::V6 => AF_INET6 as _,
                };
                rule_message.nlas = vec![Nla::FwMark(fwmark), Nla::Table(table as _)];

                self.rule_handle
                    .del(rule_message)
                    .execute()
                    .await
                    .tap_err(|err| error!(%err, table, ?ip_version, "delete route rule failed"))?;

                info!(table, ?ip_version, "delete route rule done");
            }
        }

        Ok(())
    }

    #[instrument(err)]
    pub async fn update_route(
        &mut self,
        fwmark: u32,
        route_entries: &[RouteEntry],
    ) -> anyhow::Result<()> {
        let old_table_id = self.current_table_id;
        let new_table_id = if old_table_id == TABLE_ID1 {
            TABLE_ID2
        } else {
            TABLE_ID1
        };

        self.add_route_entries(new_table_id, route_entries).await?;

        info!(new_table_id, ?route_entries, "add route entries done");

        let mut rule_add_request = self.rule_handle.add().v4();
        rule_add_request.message_mut().nlas =
            vec![Nla::FwMark(fwmark), Nla::Table(new_table_id as _)];

        rule_add_request
            .execute()
            .await
            .tap_err(|err| error!(%err, fwmark, new_table_id, "add ipv4 route rule failed"))?;

        info!(fwmark, new_table_id, "add ipv4 route rule done");

        let mut rule_add_request = self.rule_handle.add().v6();
        rule_add_request.message_mut().nlas =
            vec![Nla::FwMark(fwmark), Nla::Table(new_table_id as _)];

        rule_add_request
            .execute()
            .await
            .tap_err(|err| error!(%err, fwmark, new_table_id, "update ipv6 route rule failed"))?;

        info!(fwmark, new_table_id, "add ipv6 route rule done");

        let mut delete_rule_message = RuleMessage::default();
        delete_rule_message.header.family = AF_INET as _;
        delete_rule_message.nlas = vec![Nla::FwMark(fwmark), Nla::Table(old_table_id as _)];

        self.rule_handle
            .del(delete_rule_message)
            .execute()
            .await
            .tap_err(|err| error!(%err, fwmark, old_table_id, "delete ipv4 route rule failed"))?;

        let mut delete_rule_message = RuleMessage::default();
        delete_rule_message.header.family = AF_INET6 as _;
        delete_rule_message.nlas = vec![Nla::FwMark(fwmark), Nla::Table(old_table_id as _)];

        info!(fwmark, old_table_id, "delete ipv4 route rule done");

        self.rule_handle
            .del(delete_rule_message)
            .execute()
            .await
            .tap_err(|err| error!(%err, fwmark, old_table_id, "delete ipv6 route rule failed"))?;

        info!(fwmark, old_table_id, "delete ipv6 route rule done");

        for ip_version in [IpVersion::V4, IpVersion::V6] {
            self.flush_route(old_table_id, ip_version.clone()).await?;

            info!(old_table_id, ?ip_version, "flush old route table done");
        }

        self.current_table_id = new_table_id;

        Ok(())
    }

    async fn add_route_entries(
        &mut self,
        table: u8,
        route_rules: &[RouteEntry],
    ) -> anyhow::Result<()> {
        for route_rule in route_rules {
            let out_iface_index = self
                .link_handle
                .get()
                .match_name(route_rule.out_iface.clone())
                .execute()
                .try_next()
                .await
                .tap_err(|err| {
                    error!(%err, out_iface = ?route_rule.out_iface, "get out iface index failed");
                })?
                .ok_or_else(|| anyhow::anyhow!("out iface {} not exists", route_rule.out_iface))?;

            info!(out_iface = ?route_rule.out_iface, index = out_iface_index.header.index, "get out iface index done");

            let add_request = self
                .route_handle
                .add()
                .table(table)
                .output_interface(out_iface_index.header.index);

            let result = match route_rule.addr {
                IpAddr::V4(addr) => {
                    add_request
                        .v4()
                        .destination_prefix(addr, route_rule.prefix)
                        .execute()
                        .await
                }
                IpAddr::V6(addr) => {
                    add_request
                        .v6()
                        .destination_prefix(addr, route_rule.prefix)
                        .execute()
                        .await
                }
            };

            if let Err(err) = result {
                error!(%err, table, ?route_rule, "add route entry failed");

                return Err(err.into());
            }

            info!(table, ?route_rule, "add route entry done");
        }

        Ok(())
    }

    #[instrument(err)]
    async fn flush_route(&self, table: u8, ip_version: IpVersion) -> anyhow::Result<()> {
        let mut get_request = self.route_handle.get(ip_version.clone());
        get_request.message_mut().header.table = table;
        let route_rules = get_request
            .execute()
            .try_collect::<Vec<_>>()
            .await
            .tap_err(|err| error!(%err, ?ip_version, table, "collect table entry failed"))?;

        info!(table, ?ip_version, ?route_rules, "collect table rule done");

        for route_rule in route_rules {
            self.route_handle
                .del(route_rule)
                .execute()
                .await
                .tap_err(|err| error!(%err, table, ?ip_version, "delete route entry failed"))?;
        }

        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct RouteEntry {
    pub prefix: u8,
    pub addr: IpAddr,
    pub out_iface: String,
}
