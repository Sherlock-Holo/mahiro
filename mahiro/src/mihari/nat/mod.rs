use std::collections::{HashMap, HashSet};
use std::future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap as BpfHashMap, MapError, MapRefMut};
use aya::programs::tc::SchedClassifierLink;
use aya::programs::{tc, Link, SchedClassifier, TcAttachType};
use aya::Bpf;
use aya_log::BpfLogger;
use cidr::{Ipv4Inet, Ipv6Inet};
use derivative::Derivative;
use futures_util::{stream, StreamExt, TryStreamExt};
use netlink_packet_route::address::Nla;
use netlink_packet_route::link::nlas::Nla as LinkNla;
use rtnetlink::{AddressHandle, Handle, LinkHandle};
use tap::TapFallible;
use tokio::time;
use tracing::error;
use tracing_log::LogTracer;

use self::ip_addr::{BpfIpv4Addr, BpfIpv6Addr};

mod ip_addr;

const SNAT_EGRESS: &str = "snat_egress";
const DNAT_INGRESS: &str = "dnat_ingress";
const NIC_IPV4_MAP: &str = "NIC_IPV4_MAP";
const NIC_IPV6_MAP: &str = "NIC_IPV4_MAP";
const IPV4_MAHIRO_IP: &str = "IPV4_MAHIRO_IP";
const IPV6_MAHIRO_IP: &str = "IPV6_MAHIRO_IP";
const WATCH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Derivative)]
#[derivative(Debug)]
pub struct NatActor {
    nic_addrs: HashMap<u32, NicAddr>,
    attached_bpf_programs: HashMap<String, Vec<OwnedSchedClassifierLink>>,

    bpf: Bpf,
    #[derivative(Debug = "ignore")]
    link_handle: LinkHandle,
    #[derivative(Debug = "ignore")]
    addr_handle: AddressHandle,
    mahiro_ipv4_network: Ipv4Inet,
    mahiro_ipv6_network: Ipv6Inet,
    watch_nic_list: HashSet<String>,
}

impl NatActor {
    pub fn new(
        netlink_handle: Handle,
        mahiro_ipv4_network: Ipv4Inet,
        mahiro_ipv6_network: Ipv6Inet,
        watch_nic_list: HashSet<String>,
        bpf_prog: &Path,
    ) -> anyhow::Result<Self> {
        let mut bpf = Bpf::load_file(bpf_prog).tap_err(|err| {
            error!(%err, ?bpf_prog, "load bpf failed");
        })?;

        init_bpf_log(&mut bpf);

        Self::set_bpf_map(&mut bpf, mahiro_ipv4_network, mahiro_ipv6_network)?;

        for nic in &watch_nic_list {
            tc::qdisc_add_clsact(nic).tap_err(|err| error!(%err, %nic, "set qdisc failed"))?;
        }

        let attached_bpf_programs = Self::attach_nic(&mut bpf, &watch_nic_list)?;

        Ok(Self {
            nic_addrs: Default::default(),
            attached_bpf_programs,
            bpf,
            link_handle: netlink_handle.link(),
            addr_handle: netlink_handle.address(),
            mahiro_ipv4_network,
            mahiro_ipv6_network,
            watch_nic_list,
        })
    }

    fn attach_nic(
        bpf: &mut Bpf,
        watch_nic_list: &HashSet<String>,
    ) -> anyhow::Result<HashMap<String, Vec<OwnedSchedClassifierLink>>> {
        let mut attached_bpf_programs = HashMap::with_capacity(watch_nic_list.len() * 2);

        let snat_egress_prog: &mut SchedClassifier = bpf
            .program_mut(SNAT_EGRESS)
            .expect("snat egress bpf program miss")
            .try_into()
            .tap_err(|err| error!(%err, "get sched classifier program failed"))?;
        snat_egress_prog
            .load()
            .tap_err(|err| error!(%err, "load snat egress bpf program failed"))?;

        for nic in watch_nic_list {
            let link_id = snat_egress_prog
                .attach(nic, TcAttachType::Egress, 0)
                .tap_err(|err| error!(%err, %nic, "attach snat egress bpf program failed"))?;
            let link = snat_egress_prog
                .take_link(link_id)
                .tap_err(|err| error!(%err, "snat egress bpf take link failed"))?;
            let link = OwnedSchedClassifierLink::from(link);

            match attached_bpf_programs.get_mut(nic) {
                None => {
                    attached_bpf_programs.insert(nic.clone(), vec![link]);
                }
                Some(links) => {
                    links.push(link);
                }
            }
        }

        let dnat_ingress_prog: &mut SchedClassifier = bpf
            .program_mut(DNAT_INGRESS)
            .expect("dnat ingress bpf program miss")
            .try_into()
            .tap_err(|err| error!(%err, "get sched classifier program failed"))?;
        dnat_ingress_prog
            .load()
            .tap_err(|err| error!(%err, "load dnat ingress bpf program failed"))?;

        for nic in watch_nic_list {
            let link_id = dnat_ingress_prog
                .attach(nic, TcAttachType::Ingress, 0)
                .tap_err(|err| error!(%err, %nic, "attach dnat ingress bpf program failed"))?;
            let link = dnat_ingress_prog
                .take_link(link_id)
                .tap_err(|err| error!(%err, "dnat ingress bpf take link failed"))?;
            let link = OwnedSchedClassifierLink::from(link);

            match attached_bpf_programs.get_mut(nic) {
                None => {
                    attached_bpf_programs.insert(nic.clone(), vec![link]);
                }
                Some(links) => {
                    links.push(link);
                }
            }
        }

        Ok(attached_bpf_programs)
    }

    fn set_bpf_map(
        bpf: &mut Bpf,
        mahiro_ipv4_network: Ipv4Inet,
        mahiro_ipv6_network: Ipv6Inet,
    ) -> anyhow::Result<()> {
        Self::fn_with_ipv4_mahiro_ip(bpf, |lpm_trie| {
            let addr = mahiro_ipv4_network.address().into();
            let prefix = mahiro_ipv4_network.network_length();

            lpm_trie
                .insert(&Key::new(prefix as _, addr), 1, 0)
                .tap_err(
                    |err| error!(%err, %mahiro_ipv4_network, "insert mahiro_ipv4_network failed"),
                )?;

            Ok(())
        })?;

        Self::fn_with_ipv6_mahiro_ip(bpf, |lpm_trie| {
            let addr = mahiro_ipv6_network.address().into();
            let prefix = mahiro_ipv6_network.network_length();

            lpm_trie
                .insert(&Key::new(prefix as _, addr), 1, 0)
                .tap_err(
                    |err| error!(%err, %mahiro_ipv4_network, "insert mahiro_ipv6_network failed"),
                )?;

            Ok(())
        })
    }

    fn fn_with_nic_ipv4_map<
        F: FnOnce(BpfHashMap<MapRefMut, u32, BpfIpv4Addr>) -> anyhow::Result<()>,
    >(
        bpf: &mut Bpf,
        f: F,
    ) -> anyhow::Result<()> {
        let ipv4_mahiro_ip: BpfHashMap<_, u32, BpfIpv4Addr> = bpf
            .map_mut(NIC_IPV4_MAP)
            .expect("nic_ipv4_map miss")
            .try_into()
            .tap_err(|err| error!(%err, "get nic_ipv4_map failed"))?;

        f(ipv4_mahiro_ip)
    }

    fn fn_with_nic_ipv6_map<
        F: FnOnce(BpfHashMap<MapRefMut, u32, BpfIpv6Addr>) -> anyhow::Result<()>,
    >(
        bpf: &mut Bpf,
        f: F,
    ) -> anyhow::Result<()> {
        let ipv6_mahiro_ip: BpfHashMap<_, u32, BpfIpv6Addr> = bpf
            .map_mut(NIC_IPV6_MAP)
            .expect("nic_ipv6_map miss")
            .try_into()
            .tap_err(|err| error!(%err, "get nic_ipv6_map failed"))?;

        f(ipv6_mahiro_ip)
    }

    fn fn_with_ipv4_mahiro_ip<
        F: FnOnce(LpmTrie<MapRefMut, BpfIpv4Addr, u8>) -> anyhow::Result<()>,
    >(
        bpf: &mut Bpf,
        f: F,
    ) -> anyhow::Result<()> {
        let ipv4_mahiro_ip: LpmTrie<_, BpfIpv4Addr, u8> = bpf
            .map_mut(IPV4_MAHIRO_IP)
            .expect("ipv4_mahiro_ip lpm trie miss")
            .try_into()
            .tap_err(|err| error!(%err, "get ipv4_mahiro_ip lpm trie failed"))?;

        f(ipv4_mahiro_ip)
    }

    fn fn_with_ipv6_mahiro_ip<
        F: FnOnce(LpmTrie<MapRefMut, BpfIpv6Addr, u8>) -> anyhow::Result<()>,
    >(
        bpf: &mut Bpf,
        f: F,
    ) -> anyhow::Result<()> {
        let ipv6_mahiro_ip: LpmTrie<_, BpfIpv6Addr, u8> = bpf
            .map_mut(IPV6_MAHIRO_IP)
            .expect("ipv6_mahiro_ip lpm trie miss")
            .try_into()
            .tap_err(|err| error!(%err, "get ipv6_mahiro_ip lpm trie failed"))?;

        f(ipv6_mahiro_ip)
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.run_circle().await?;

            time::sleep(WATCH_INTERVAL).await;
        }
    }

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        self.update_nic_addrs().await
    }

    async fn update_nic_addrs(&mut self) -> anyhow::Result<()> {
        let new_nic_addrs = self.collect_nic_addrs().await?;
        let (deleted_addrs, add_addrs) = self.diff_nic_addrs(new_nic_addrs);
        for (index, addr) in deleted_addrs {
            if addr.ipv4.is_some() {
                Self::fn_with_nic_ipv4_map(&mut self.bpf, |mut map| match map.remove(&index) {
                    Err(MapError::KeyNotFound) => Ok(()),
                    Err(err) => {
                        error!(%err, index, "remove deleted ipv4 addr failed");

                        Err(err.into())
                    }
                    Ok(_) => Ok(()),
                })?;
            }

            if addr.ipv6.is_some() {
                Self::fn_with_nic_ipv6_map(&mut self.bpf, |mut map| match map.remove(&index) {
                    Err(MapError::KeyNotFound) => Ok(()),
                    Err(err) => {
                        error!(%err, index, "remove deleted ipv6 addr failed");

                        Err(err.into())
                    }
                    Ok(_) => Ok(()),
                })?;
            }
        }

        for (index, addr) in add_addrs {
            if let Some(addr) = addr.ipv4 {
                Self::fn_with_nic_ipv4_map(&mut self.bpf, |mut map| {
                    map.insert(index, addr.into(), 0)
                        .tap_err(|err| error!(%err, index, %addr, "add nic ipv4 addr failed"))?;

                    Ok(())
                })?;
            }

            if let Some(addr) = addr.ipv6 {
                Self::fn_with_nic_ipv6_map(&mut self.bpf, |mut map| {
                    map.insert(index, addr.into(), 0)
                        .tap_err(|err| error!(%err, index, %addr, "add nic ipv6 addr failed"))?;

                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn diff_nic_addrs(
        &self,
        new_nic_addrs: HashMap<u32, NicAddr>,
    ) -> (HashMap<u32, NicAddr>, HashMap<u32, NicAddr>) {
        let mut deleted_addrs = HashMap::new();
        let mut add_addrs = HashMap::new();
        for (index, addr) in &self.nic_addrs {
            match new_nic_addrs.get(index) {
                None => {
                    deleted_addrs.insert(*index, addr.clone());
                }

                Some(new_addr) => {
                    if new_addr != addr {
                        deleted_addrs.insert(*index, addr.clone());
                    }
                }
            }
        }
        for (index, addr) in &new_nic_addrs {
            match self.nic_addrs.get(index) {
                None => {
                    add_addrs.insert(*index, addr.clone());
                }

                Some(old_addr) => {
                    if addr != old_addr {
                        add_addrs.insert(*index, addr.clone());
                    }
                }
            }
        }

        (deleted_addrs, add_addrs)
    }

    async fn collect_nic_addrs(&mut self) -> anyhow::Result<HashMap<u32, NicAddr>> {
        let nic_index_list = self
            .link_handle
            .get()
            .execute()
            .try_filter_map(|nic| {
                let option = nic
                    .nlas
                    .into_iter()
                    .find(|nla| matches!(nla, LinkNla::IfName(_)))
                    .map(|nla| match nla {
                        LinkNla::IfName(name) => name,
                        _ => unreachable!(),
                    })
                    .and_then(|name| {
                        self.watch_nic_list
                            .contains(&name)
                            .then_some(nic.header.index)
                    });

                future::ready(Ok(option))
            })
            .try_collect::<Vec<_>>()
            .await
            .tap_err(|err| error!(%err, "collect nic index failed"))?;

        stream::iter(nic_index_list)
            .map(Ok::<_, anyhow::Error>)
            .and_then(|index| {
                let request = self.addr_handle.get().set_link_index_filter(index);
                async move {
                    let addrs = request
                        .execute()
                        .try_filter_map(|addr| async move {
                            let addr = match addr
                                .nlas
                                .into_iter()
                                .find(|nla| matches!(nla, Nla::Address(_)))
                            {
                                None => return Ok(None),
                                Some(Nla::Address(addr)) => addr,
                                _ => unreachable!(),
                            };

                            if addr.len() == 4 {
                                Ok(Some(IpAddr::V4(Ipv4Addr::new(
                                    addr[0], addr[1], addr[2], addr[3],
                                ))))
                            } else if addr.len() == 32 {
                                let addr: [u8; 16] = addr.as_slice().try_into().unwrap();

                                Ok(Some(IpAddr::V6(Ipv6Addr::from(addr))))
                            } else {
                                Ok(None)
                            }
                        })
                        .try_filter(|addr| {
                            let result = match addr {
                                IpAddr::V4(addr) => !addr.is_link_local(),
                                IpAddr::V6(addr) => !addr.is_unicast_link_local(),
                            };

                            future::ready(result)
                        })
                        .try_collect::<Vec<_>>()
                        .await?;

                    let ipv4 = addrs.iter().find(|ip| ip.is_ipv4()).map(|ip| match ip {
                        IpAddr::V4(ip) => *ip,
                        IpAddr::V6(_) => unreachable!(),
                    });
                    let ipv6 = addrs.iter().find(|ip| ip.is_ipv6()).map(|ip| match ip {
                        IpAddr::V6(ip) => *ip,
                        IpAddr::V4(_) => unreachable!(),
                    });

                    Ok((index, NicAddr { ipv4, ipv6 }))
                }
            })
            .try_filter(|(_, nic_addr)| {
                future::ready(nic_addr.ipv4.is_some() || nic_addr.ipv6.is_some())
            })
            .try_collect()
            .await
    }
}

#[derive(Debug)]
struct OwnedSchedClassifierLink(Option<SchedClassifierLink>);

impl From<SchedClassifierLink> for OwnedSchedClassifierLink {
    fn from(value: SchedClassifierLink) -> Self {
        Self(Some(value))
    }
}

impl Drop for OwnedSchedClassifierLink {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().detach();
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct NicAddr {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

fn init_bpf_log(bpf: &mut Bpf) {
    LogTracer::builder().init().unwrap();

    BpfLogger::init(bpf).unwrap();
}
