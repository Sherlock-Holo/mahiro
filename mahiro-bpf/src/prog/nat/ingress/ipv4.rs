use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::helpers::bpf_ktime_get_boot_ns;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::warn;
use network_types::eth::EthHdr;
use network_types::icmp::IcmpHdr;
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::conntrack::ipv4::{ConntrackEntry, ConntrackKey};
use crate::conntrack::{ipv4 as ipv4_conntrack, ConntrackType, ProtocolType};
use crate::context_ext::ContextExt;
use crate::ip_addr::Ipv4Addr;
use crate::nat::{ipv4, L4Hdr};

pub fn ipv4_ingress(ctx: &TcContext, _eth_hdr: &mut EthHdr) -> Result<i32, ()> {
    let ipv4_hdr = ctx.load_ptr::<Ipv4Hdr>(EthHdr::LEN).ok_or(())?;
    let src_addr = Ipv4Addr::from(ipv4_hdr.src_addr);
    let dst_addr = Ipv4Addr::from(ipv4_hdr.dst_addr);

    match ipv4_hdr.proto {
        IpProto::Tcp => ipv4_tcp_ingress(ctx, ipv4_hdr, src_addr, dst_addr),
        IpProto::Udp => ipv4_udp_ingress(ctx, ipv4_hdr, src_addr, dst_addr),
        IpProto::Icmp => ipv4_icmp_ingress(ctx, ipv4_hdr, src_addr, dst_addr),

        _ => Ok(TC_ACT_OK),
    }
}

fn ipv4_tcp_ingress(
    ctx: &TcContext,
    ipv4_hdr: &mut Ipv4Hdr,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
) -> Result<i32, ()> {
    let tcp_hdr = ctx
        .load_ptr::<TcpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(())?;

    let src_port = tcp_hdr.source;
    let dst_port = tcp_hdr.dest;
    let protocol_type = ProtocolType::Tcp;
    let dnat_key = ConntrackKey::new(src_addr, dst_addr, src_port, dst_port, protocol_type);

    // tcp RST packet can let us remove conntrack immediately
    if tcp_hdr.rst() > 0 {
        return match ipv4_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
            None => Ok(TC_ACT_OK),
            Some(dnat_entry) => {
                let dnat_dst_addr = dnat_entry.get_dst_addr();

                let snat_key = ConntrackKey::new(
                    dnat_entry.get_dst_addr(),
                    dnat_entry.get_src_addr(),
                    dnat_entry.get_dst_port(),
                    dnat_entry.get_src_port(),
                    protocol_type,
                );

                let _ = ipv4_conntrack::remove_conntrack_entry(&snat_key, ConntrackType::Snat);
                let _ = ipv4_conntrack::remove_conntrack_entry(&dnat_key, ConntrackType::Dnat);

                ipv4::ipv4_dnat(
                    ctx,
                    ipv4_hdr,
                    L4Hdr::Tcp(tcp_hdr),
                    Some(dnat_dst_addr),
                    None,
                )
                .map_err(|_| ())
            }
        };
    }

    let dnat_dst_addr = match ipv4_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
        None => return Ok(TC_ACT_OK),
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

            match ipv4_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
                None => {
                    warn!(ctx, "ipv4 tcp ingress conntrack dnat miss, need rebuild");

                    let snat_entry =
                        ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);

                    ipv4_conntrack::insert_conntrack(&snat_key, &snat_entry, ConntrackType::Snat)
                        .map_err(|_| ())?;
                }

                Some(snat_entry) => {
                    snat_entry.set_update_time(update_time);
                }
            }

            dnat_entry.get_dst_addr()
        }
    };

    ipv4::ipv4_dnat(
        ctx,
        ipv4_hdr,
        L4Hdr::Tcp(tcp_hdr),
        Some(dnat_dst_addr),
        None,
    )
    .map_err(|_| ())
}

fn ipv4_udp_ingress(
    ctx: &TcContext,
    ipv4_hdr: &mut Ipv4Hdr,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
) -> Result<i32, ()> {
    let udp_hdr = ctx
        .load_ptr::<UdpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(())?;

    let src_port = udp_hdr.source;
    let dst_port = udp_hdr.dest;
    let protocol_type = ProtocolType::Udp;
    let dnat_key = ConntrackKey::new(src_addr, dst_addr, src_port, dst_port, protocol_type);

    let dnat_dst_addr = match ipv4_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
        None => return Ok(TC_ACT_OK),
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

            match ipv4_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
                None => {
                    warn!(ctx, "ipv4 udp ingress conntrack dnat miss, need rebuild");

                    let snat_entry =
                        ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);

                    ipv4_conntrack::insert_conntrack(&snat_key, &snat_entry, ConntrackType::Snat)
                        .map_err(|_| ())?;
                }

                Some(snat_entry) => {
                    snat_entry.set_update_time(update_time);
                }
            }

            dnat_entry.get_dst_addr()
        }
    };

    ipv4::ipv4_dnat(
        ctx,
        ipv4_hdr,
        L4Hdr::Udp(udp_hdr),
        Some(dnat_dst_addr),
        None,
    )
    .map_err(|_| ())
}

fn ipv4_icmp_ingress(
    ctx: &TcContext,
    ipv4_hdr: &mut Ipv4Hdr,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
) -> Result<i32, ()> {
    let icmp_hdr = ctx
        .load_ptr::<IcmpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(())?;

    let dnat_key = ConntrackKey::new(src_addr, dst_addr, 0, 0, ProtocolType::Icmp);

    let dnat_dst_addr = match ipv4_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
        None => return Ok(TC_ACT_OK),
        Some(dnat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            dnat_entry.set_update_time(update_time);

            let snat_key = ConntrackKey::new(
                dnat_entry.get_dst_addr(),
                dnat_entry.get_src_addr(),
                dnat_entry.get_dst_port(),
                dnat_entry.get_src_port(),
                ProtocolType::Icmp,
            );

            match ipv4_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
                None => {
                    warn!(ctx, "ipv4 icmp ingress conntrack dnat miss, need rebuild");

                    let snat_entry =
                        ConntrackEntry::new(dst_addr, src_addr, 0, 0, ProtocolType::Icmp);

                    ipv4_conntrack::insert_conntrack(&snat_key, &snat_entry, ConntrackType::Snat)
                        .map_err(|_| ())?;
                }

                Some(snat_entry) => {
                    snat_entry.set_update_time(update_time);
                }
            }

            dnat_entry.get_dst_addr()
        }
    };

    ipv4::ipv4_dnat(
        ctx,
        ipv4_hdr,
        L4Hdr::Icmp(icmp_hdr),
        Some(dnat_dst_addr),
        None,
    )
    .map_err(|_| ())
}
