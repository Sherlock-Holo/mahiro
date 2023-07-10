use core::ptr;

use aya_bpf::helpers::bpf_ktime_get_boot_ns;
use aya_bpf::macros::map;
use aya_bpf::maps::PerCpuArray;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::warn;
use network_types::eth::EthHdr;
use network_types::icmp::IcmpHdr;
use network_types::ip::{IpProto, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::conntrack::ipv6::{ConntrackEntry, ConntrackKey};
use crate::conntrack::{ipv6 as ipv6_conntrack, ConntrackType, ProtocolType};
use crate::context_ext::ContextExt;
use crate::ip_addr::Ipv6Addr;
use crate::nat::{ipv6, L4Hdr};

#[map(name = "IPV6_INGRESS_SRC_HEAP")]
static IPV6_INGRESS_SRC_HEAP: PerCpuArray<Ipv6Addr> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "IPV6_INGRESS_DST_HEAP")]
static IPV6_INGRESS_DST_HEAP: PerCpuArray<Ipv6Addr> = PerCpuArray::with_max_entries(1, 0);

pub fn ipv6_ingress(ctx: &TcContext, _eth_hdr: &mut EthHdr) -> Result<bool, ()> {
    let ipv6_hdr = ctx.load_ptr::<Ipv6Hdr>(EthHdr::LEN).ok_or(())?;
    let src_addr = IPV6_INGRESS_SRC_HEAP.get_ptr_mut(0).ok_or(())?;
    let dst_addr = IPV6_INGRESS_DST_HEAP.get_ptr_mut(0).ok_or(())?;
    let (src_addr, dst_addr) = unsafe {
        ptr::copy_nonoverlapping(
            ipv6_hdr.src_addr.in6_u.u6_addr8.as_ptr() as *const _,
            src_addr,
            1,
        );
        ptr::copy_nonoverlapping(
            ipv6_hdr.dst_addr.in6_u.u6_addr8.as_ptr() as *const _,
            dst_addr,
            1,
        );

        (&*src_addr, &*dst_addr)
    };

    match ipv6_hdr.next_hdr {
        IpProto::Tcp => ipv6_tcp_ingress(ctx, ipv6_hdr, src_addr, dst_addr),
        IpProto::Udp => ipv6_udp_ingress(ctx, ipv6_hdr, src_addr, dst_addr),
        IpProto::Ipv6Icmp => ipv6_icmp_ingress(ctx, ipv6_hdr, src_addr, dst_addr),

        _ => Ok(false),
    }
}

fn ipv6_tcp_ingress(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
) -> Result<bool, ()> {
    let tcp_hdr = match ctx.load_ptr::<TcpHdr>(EthHdr::LEN + Ipv6Hdr::LEN) {
        None => return Ok(false),
        Some(tcp_hdr) => tcp_hdr,
    };

    let src_port = tcp_hdr.source;
    let dst_port = tcp_hdr.dest;
    let protocol_type = ProtocolType::Tcp;
    let dnat_key = ConntrackKey::new(*src_addr, *dst_addr, src_port, dst_port, protocol_type);

    // tcp RST packet can let us remove conntrack immediately
    if tcp_hdr.rst() > 0 {
        return match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
            None => Ok(false),
            Some(dnat_entry) => {
                let dnat_dst_addr = dnat_entry.get_dst_addr();

                let snat_key = ConntrackKey::new(
                    dnat_entry.get_dst_addr(),
                    dnat_entry.get_src_addr(),
                    dnat_entry.get_dst_port(),
                    dnat_entry.get_src_port(),
                    protocol_type,
                );

                let _ = ipv6_conntrack::remove_conntrack_entry(&snat_key, ConntrackType::Snat);
                let _ = ipv6_conntrack::remove_conntrack_entry(&dnat_key, ConntrackType::Dnat);

                ipv6::ipv6_dnat(
                    ctx,
                    ipv6_hdr,
                    L4Hdr::Tcp(tcp_hdr),
                    Some(dnat_dst_addr),
                    None,
                )
                .map_err(|_| ())?;

                Ok(true)
            }
        };
    }

    let dnat_dst_addr = match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
        None => return Ok(false),
        Some(dnat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            dnat_entry.set_update_time(update_time);

            let snat_key = ConntrackKey::new(
                dnat_entry.get_dst_addr(),
                dnat_entry.get_src_addr(),
                dnat_entry.get_dst_port(),
                dnat_entry.get_src_port(),
                protocol_type,
            );

            match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
                None => {
                    warn!(ctx, "ipv6 tcp ingress conntrack dnat miss, need rebuild");

                    let snat_entry = ConntrackEntry::new(
                        *dst_addr,
                        *src_addr,
                        dst_port,
                        src_port,
                        protocol_type,
                    );

                    ipv6_conntrack::insert_conntrack(&snat_key, &snat_entry, ConntrackType::Snat)
                        .map_err(|_| ())?;
                }

                Some(snat_entry) => {
                    snat_entry.set_update_time(update_time);
                }
            }

            dnat_entry.get_dst_addr()
        }
    };

    ipv6::ipv6_dnat(
        ctx,
        ipv6_hdr,
        L4Hdr::Tcp(tcp_hdr),
        Some(dnat_dst_addr),
        None,
    )
    .map_err(|_| ())?;

    Ok(true)
}

fn ipv6_udp_ingress(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
) -> Result<bool, ()> {
    // TODO why sometimes mahiro udp frame can't get the udp header?
    let udp_hdr = match ctx.load_ptr::<UdpHdr>(EthHdr::LEN + Ipv6Hdr::LEN) {
        None => return Ok(false),
        Some(udp_hdr) => udp_hdr,
    };

    let src_port = udp_hdr.source;
    let dst_port = udp_hdr.dest;
    let protocol_type = ProtocolType::Udp;
    let dnat_key = ConntrackKey::new(*src_addr, *dst_addr, src_port, dst_port, protocol_type);

    let dnat_dst_addr = match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
        None => return Ok(false),
        Some(dnat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            dnat_entry.set_update_time(update_time);

            let snat_key = ConntrackKey::new(
                dnat_entry.get_dst_addr(),
                dnat_entry.get_src_addr(),
                dnat_entry.get_dst_port(),
                dnat_entry.get_src_port(),
                protocol_type,
            );

            match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
                None => {
                    warn!(ctx, "ipv6 udp ingress conntrack dnat miss, need rebuild");

                    let snat_entry = ConntrackEntry::new(
                        *dst_addr,
                        *src_addr,
                        dst_port,
                        src_port,
                        protocol_type,
                    );

                    ipv6_conntrack::insert_conntrack(&snat_key, &snat_entry, ConntrackType::Snat)
                        .map_err(|_| ())?;
                }

                Some(snat_entry) => {
                    snat_entry.set_update_time(update_time);
                }
            }

            dnat_entry.get_dst_addr()
        }
    };

    ipv6::ipv6_dnat(
        ctx,
        ipv6_hdr,
        L4Hdr::Udp(udp_hdr),
        Some(dnat_dst_addr),
        None,
    )
    .map_err(|_| ())?;

    Ok(true)
}

fn ipv6_icmp_ingress(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
) -> Result<bool, ()> {
    let icmp_hdr = match ctx.load_ptr::<IcmpHdr>(EthHdr::LEN + Ipv6Hdr::LEN) {
        None => return Ok(false),
        Some(icmp_hdr) => icmp_hdr,
    };

    let protocol_type = ProtocolType::Icmp;
    let dnat_key = ConntrackKey::new(*src_addr, *dst_addr, 0, 0, protocol_type);

    let dnat_dst_addr = match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
        None => return Ok(false),
        Some(dnat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            dnat_entry.set_update_time(update_time);

            let snat_key = ConntrackKey::new(
                dnat_entry.get_dst_addr(),
                dnat_entry.get_src_addr(),
                dnat_entry.get_dst_port(),
                dnat_entry.get_src_port(),
                protocol_type,
            );

            match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
                None => {
                    warn!(ctx, "ipv6 icmp ingress conntrack dnat miss, need rebuild");

                    let snat_entry = ConntrackEntry::new(*dst_addr, *src_addr, 0, 0, protocol_type);

                    ipv6_conntrack::insert_conntrack(&snat_key, &snat_entry, ConntrackType::Snat)
                        .map_err(|_| ())?;
                }

                Some(snat_entry) => {
                    snat_entry.set_update_time(update_time);
                }
            }

            dnat_entry.get_dst_addr()
        }
    };

    ipv6::ipv6_dnat(
        ctx,
        ipv6_hdr,
        L4Hdr::Icmp(icmp_hdr),
        Some(dnat_dst_addr),
        None,
    )
    .map_err(|_| ())?;

    Ok(true)
}
