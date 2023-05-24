use std::collections::{HashMap, HashSet};
use std::future;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap as BpfHashMap, MapData, MapError};
use aya::programs::tc::SchedClassifierLink;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Bpf;
use aya_log::BpfLogger;
use derivative::Derivative;
use either::Either;
use futures_util::{stream, StreamExt, TryStreamExt};
use ipnet::{Ipv4Net, Ipv6Net};
use netlink_packet_route::address::Nla;
use netlink_packet_route::link::nlas::Nla as LinkNla;
use rtnetlink::{AddressHandle, Handle, LinkHandle};
use tap::TapFallible;
use tokio::time;
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, error, info};
use tracing_log::LogTracer;

use self::ip_addr::{BpfIpv4Addr, BpfIpv6Addr};
use crate::util::OwnedLink;

mod ip_addr;

const SNAT_EGRESS: &str = "snat_egress";
const DNAT_INGRESS: &str = "dnat_ingress";
const DNAT_INGRESS_WITH_REDIRECT_ROUTE: &str = "dnat_ingress_with_redirect";
const REDIRECT_ROUTE: &str = "redirect_route";
const NIC_IPV4_MAP: &str = "NIC_IPV4_MAP";
const NIC_IPV6_MAP: &str = "NIC_IPV6_MAP";
const IPV4_MAHIRO_IP: &str = "IPV4_MAHIRO_IP";
const IPV6_MAHIRO_IP: &str = "IPV6_MAHIRO_IP";
const WATCH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Derivative)]
#[derivative(Debug)]
pub struct NatActor {
    nic_addrs: HashMap<u32, NicAddr>,
    attached_bpf_programs: HashMap<String, Vec<OwnedLink<SchedClassifierLink>>>,

    bpf: Bpf,
    #[derivative(Debug = "ignore")]
    link_handle: LinkHandle,
    #[derivative(Debug = "ignore")]
    addr_handle: AddressHandle,
    mahiro_ipv4_network: Ipv4Net,
    mahiro_ipv6_network: Ipv6Net,
    watch_nic_list: HashSet<String>,
}

impl NatActor {
    pub fn new(
        netlink_handle: Handle,
        mahiro_ipv4_network: Ipv4Net,
        mahiro_ipv6_network: Ipv6Net,
        watch_nic_list: HashSet<String>,
        bpf_forward: bool,
        mihari_nic: &str,
        mut bpf: Bpf,
    ) -> anyhow::Result<Self> {
        init_bpf_log(&mut bpf);

        Self::set_bpf_map(&mut bpf, mahiro_ipv4_network, mahiro_ipv6_network)?;

        {
            let watch_nic_list = watch_nic_list.iter().map(|nic| nic.as_str());
            let watch_nic_list = if bpf_forward {
                Either::Left(watch_nic_list.chain([mihari_nic]))
            } else {
                Either::Right(watch_nic_list)
            };

            for nic in watch_nic_list {
                match tc::qdisc_add_clsact(nic) {
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,

                    Err(err) => {
                        error!(%err, %nic, "set nic qdisc failed");

                        return Err(err.into());
                    }

                    Ok(_) => {}
                }
            }
        }

        let mut attached_bpf_programs = Self::attach_nic(&mut bpf, bpf_forward, &watch_nic_list)?;
        if bpf_forward {
            let redirect_route_link = Self::attach_redirect_route_nic(&mut bpf, mihari_nic)?;
            attached_bpf_programs.insert(mihari_nic.to_string(), vec![redirect_route_link]);
        }

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
        bpf_forward: bool,
        watch_nic_list: &HashSet<String>,
    ) -> anyhow::Result<HashMap<String, Vec<OwnedLink<SchedClassifierLink>>>> {
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
                .attach(nic, TcAttachType::Egress)
                .tap_err(|err| error!(%err, %nic, "attach snat egress bpf program failed"))?;
            let link = snat_egress_prog
                .take_link(link_id)
                .tap_err(|err| error!(%err, "snat egress bpf take link failed"))?;
            let link = OwnedLink::from(link);

            info!(%nic, "attach snat egress bpf program to nic done");

            attached_bpf_programs.insert(nic.clone(), vec![link]);
        }

        let dnat_prog_name = if bpf_forward {
            DNAT_INGRESS_WITH_REDIRECT_ROUTE
        } else {
            DNAT_INGRESS
        };
        let dnat_ingress_prog: &mut SchedClassifier = bpf
            .program_mut(dnat_prog_name)
            .unwrap_or_else(|| panic!("dnat ingress bpf program {dnat_prog_name} miss"))
            .try_into()
            .tap_err(|err| error!(%err, dnat_prog_name, "get sched classifier program failed"))?;
        dnat_ingress_prog
            .load()
            .tap_err(|err| error!(%err, dnat_prog_name, "load dnat ingress bpf program failed"))?;

        for nic in watch_nic_list {
            let link_id = dnat_ingress_prog
                .attach(nic, TcAttachType::Ingress)
                .tap_err(|err| error!(%err, %nic, dnat_prog_name, "attach dnat ingress bpf program failed"))?;
            let link = dnat_ingress_prog
                .take_link(link_id)
                .tap_err(|err| error!(%err, dnat_prog_name, "dnat ingress bpf take link failed"))?;
            let link = OwnedLink::from(link);

            info!(%nic, dnat_prog_name, "attach dnat ingress bpf program to nic done");

            attached_bpf_programs.get_mut(nic).unwrap().push(link);
        }

        Ok(attached_bpf_programs)
    }

    fn attach_redirect_route_nic(
        bpf: &mut Bpf,
        mihari_nic: &str,
    ) -> anyhow::Result<OwnedLink<SchedClassifierLink>> {
        let redirect_route_prog: &mut SchedClassifier = bpf
            .program_mut(REDIRECT_ROUTE)
            .expect("redirect route bpf program miss")
            .try_into()
            .tap_err(|err| error!(%err, "get sched classifier program failed"))?;
        redirect_route_prog
            .load()
            .tap_err(|err| error!(%err, "load redirect route bpf program failed"))?;

        let link_id = redirect_route_prog
            .attach(mihari_nic, TcAttachType::Ingress)
            .tap_err(|err| error!(%err, mihari_nic, "attach redirect route bpf program failed"))?;
        let link = redirect_route_prog
            .take_link(link_id)
            .tap_err(|err| error!(%err, "redirect route bpf take link failed"))?;
        let link = OwnedLink::from(link);

        Ok(link)
    }

    fn set_bpf_map(
        bpf: &mut Bpf,
        mahiro_ipv4_network: Ipv4Net,
        mahiro_ipv6_network: Ipv6Net,
    ) -> anyhow::Result<()> {
        Self::fn_with_ipv4_mahiro_ip(bpf, |mut lpm_trie| {
            let addr = mahiro_ipv4_network.addr().into();
            let prefix = mahiro_ipv4_network.prefix_len();

            lpm_trie
                .insert(&Key::new(prefix as _, addr), 1, 0)
                .tap_err(
                    |err| error!(%err, %mahiro_ipv4_network, "insert mahiro_ipv4_network failed"),
                )?;

            Ok(())
        })?;

        Self::fn_with_ipv6_mahiro_ip(bpf, |mut lpm_trie| {
            let addr = mahiro_ipv6_network.addr().into();
            let prefix = mahiro_ipv6_network.prefix_len();

            lpm_trie
                .insert(&Key::new(prefix as _, addr), 1, 0)
                .tap_err(
                    |err| error!(%err, %mahiro_ipv4_network, "insert mahiro_ipv6_network failed"),
                )?;

            Ok(())
        })
    }

    fn fn_with_nic_ipv4_map<
        F: FnOnce(BpfHashMap<&mut MapData, u32, BpfIpv4Addr>) -> anyhow::Result<()>,
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
        F: FnOnce(BpfHashMap<&mut MapData, u32, BpfIpv6Addr>) -> anyhow::Result<()>,
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
        F: FnOnce(LpmTrie<&mut MapData, BpfIpv4Addr, u8>) -> anyhow::Result<()>,
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
        F: FnOnce(LpmTrie<&mut MapData, BpfIpv6Addr, u8>) -> anyhow::Result<()>,
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
        let mut interval_stream = IntervalStream::new(time::interval(WATCH_INTERVAL));

        while (interval_stream.next().await).is_some() {
            if let Err(err) = self.run_circle().await {
                error!(%err, "update nic addr failed");
            }
        }

        unreachable!("interval stream stopped")
    }

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        self.update_nic_addrs().await
    }

    async fn update_nic_addrs(&mut self) -> anyhow::Result<()> {
        let new_nic_addrs = self.collect_nic_addrs().await?;

        debug!(?new_nic_addrs, "collect nic addrs done");

        let (deleted_addrs, add_addrs) = self.diff_nic_addrs(new_nic_addrs);

        debug!(?deleted_addrs, ?add_addrs, "diff nic addrs done");

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

            self.nic_addrs.remove(&index);
        }

        for (index, addr) in add_addrs {
            if let Some(addr) = addr.ipv4 {
                Self::fn_with_nic_ipv4_map(&mut self.bpf, |mut map| {
                    map.insert(index, &addr.into(), 0)
                        .tap_err(|err| error!(%err, index, %addr, "add nic ipv4 addr failed"))?;

                    Ok(())
                })?;
            }

            if let Some(addr) = addr.ipv6 {
                Self::fn_with_nic_ipv6_map(&mut self.bpf, |mut map| {
                    map.insert(index, &addr.into(), 0)
                        .tap_err(|err| error!(%err, index, %addr, "add nic ipv6 addr failed"))?;

                    Ok(())
                })?;
            }

            self.nic_addrs.insert(index, addr);
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
                    deleted_addrs.insert(*index, *addr);
                }

                Some(new_addr) => {
                    if new_addr != addr {
                        deleted_addrs.insert(*index, *addr);
                    }
                }
            }
        }
        for (index, addr) in &new_nic_addrs {
            match self.nic_addrs.get(index) {
                None => {
                    add_addrs.insert(*index, *addr);
                }

                Some(old_addr) => {
                    if addr != old_addr {
                        add_addrs.insert(*index, *addr);
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
                            } else if addr.len() == 16 {
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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct NicAddr {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

fn init_bpf_log(bpf: &mut Bpf) {
    LogTracer::builder().init().unwrap();

    BpfLogger::init(bpf).unwrap();
}
