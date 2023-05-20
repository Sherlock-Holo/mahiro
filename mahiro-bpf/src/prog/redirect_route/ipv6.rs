use aya_bpf::bindings::{__u32, TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::helpers::bpf_ktime_get_boot_ns;
use aya_bpf::maps::lpm_trie::Key;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::{debug, error, warn};
use network_types::icmp::IcmpHdr;
use network_types::ip::{IpProto, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::conntrack::ipv6::{self as ipv6_conntrack, ConntrackEntry, ConntrackKey, ConntrackPair};
use crate::conntrack::{ConntrackType, ProtocolType};
use crate::context_ext::ContextExt;
use crate::ip_addr::Ipv6Addr;
use crate::map::{IPV6_MAHIRO_IP, NIC_IPV6_MAP};
use crate::nat::{ipv6, L4Hdr};

pub fn ipv6_redirect_route_snat(ctx: &TcContext, egress_nic_index: __u32) -> Result<i32, ()> {
    let ipv6_hdr = ctx.load_ptr::<Ipv6Hdr>(0).ok_or(())?;
    let src_addr = Ipv6Addr::from(unsafe { ipv6_hdr.src_addr.in6_u.u6_addr8 });
    let key = Key::new(128, src_addr);

    // the src ipv6 is not in mahiro network
    if IPV6_MAHIRO_IP.get(&key).copied().unwrap_or(0) == 0 {
        return Ok(TC_ACT_OK);
    }

    let nic_ip = unsafe {
        match NIC_IPV6_MAP.get(&egress_nic_index).copied() {
            None => {
                error!(ctx, "egress nic index {} has no ipv6", egress_nic_index);

                return Ok(TC_ACT_SHOT);
            }
            Some(nic_index) => nic_index,
        }
    };

    match ipv6_hdr.next_hdr {
        IpProto::Tcp => ipv6_tcp_redirect_route(ctx, ipv6_hdr, nic_ip),
        IpProto::Udp => ipv6_udp_redirect_route(ctx, ipv6_hdr, nic_ip),
        IpProto::Ipv6Icmp => ipv6_icmp_redirect_route(ctx, ipv6_hdr, nic_ip),

        _ => Ok(TC_ACT_OK),
    }
}

fn ipv6_tcp_redirect_route(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    nic_ip: Ipv6Addr,
) -> Result<i32, ()> {
    let tcp_hdr = ctx.load_ptr::<TcpHdr>(Ipv6Hdr::LEN).ok_or(())?;

    let src_addr = Ipv6Addr::from(unsafe { ipv6_hdr.src_addr.in6_u.u6_addr8 });
    let dst_addr = Ipv6Addr::from(unsafe { ipv6_hdr.dst_addr.in6_u.u6_addr8 });
    let src_port = tcp_hdr.source;
    let dst_port = tcp_hdr.dest;
    let protocol_type = ProtocolType::Tcp;

    let snat_key = ConntrackKey::new(src_addr, dst_addr, src_port, dst_port, protocol_type);
    match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            // tcp packet is not SYN
            if tcp_hdr.syn() == 0 || tcp_hdr.ack() > 0 {
                debug!(ctx, "drop invalid tcp packet");

                return Ok(TC_ACT_SHOT);
            }

            let snat_entry =
                ConntrackEntry::new(nic_ip, dst_addr, src_port, dst_port, protocol_type);
            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, dst_port, src_port, protocol_type);
            let dnat_entry =
                ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv6_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv6 tcp redirect route insert conntrack failed");

                return Ok(TC_ACT_SHOT);
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, dst_port, src_port, protocol_type);

            match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(
                        ctx,
                        "ipv6 tcp redirect route conntrack dnat miss, need rebuild"
                    );

                    let dnat_entry =
                        ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);

                    if ipv6_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv6 tcp redirect route insert conntrack dnat failed");

                        return Ok(TC_ACT_SHOT);
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    if ipv6::ipv6_snat(ctx, ipv6_hdr, L4Hdr::Tcp(tcp_hdr), Some(nic_ip), None).is_err() {
        error!(ctx, "ipv6 tcp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}

fn ipv6_udp_redirect_route(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    nic_ip: Ipv6Addr,
) -> Result<i32, ()> {
    let udp_hdr = ctx.load_ptr::<UdpHdr>(Ipv6Hdr::LEN).ok_or(())?;

    let src_addr = Ipv6Addr::from(unsafe { ipv6_hdr.src_addr.in6_u.u6_addr8 });
    let dst_addr = Ipv6Addr::from(unsafe { ipv6_hdr.dst_addr.in6_u.u6_addr8 });
    let src_port = udp_hdr.source;
    let dst_port = udp_hdr.dest;
    let protocol_type = ProtocolType::Udp;

    let snat_key = ConntrackKey::new(src_addr, dst_addr, src_port, dst_port, protocol_type);
    match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            let snat_entry =
                ConntrackEntry::new(nic_ip, dst_addr, src_port, dst_port, protocol_type);
            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, dst_port, src_port, protocol_type);
            let dnat_entry =
                ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv6_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv6 udp redirect route insert conntrack failed");

                return Ok(TC_ACT_SHOT);
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, dst_port, src_port, protocol_type);

            match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(
                        ctx,
                        "ipv6 udp redirect route conntrack dnat miss, need rebuild"
                    );

                    let dnat_entry =
                        ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);

                    if ipv6_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv6 udp redirect route insert conntrack dnat failed");

                        return Ok(TC_ACT_SHOT);
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    if ipv6::ipv6_snat(ctx, ipv6_hdr, L4Hdr::Udp(udp_hdr), Some(nic_ip), None).is_err() {
        error!(ctx, "ipv6 udp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}

fn ipv6_icmp_redirect_route(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    nic_ip: Ipv6Addr,
) -> Result<i32, ()> {
    let icmp_hdr = ctx.load_ptr::<IcmpHdr>(Ipv6Hdr::LEN).ok_or(())?;

    let src_addr = Ipv6Addr::from(unsafe { ipv6_hdr.src_addr.in6_u.u6_addr8 });
    let dst_addr = Ipv6Addr::from(unsafe { ipv6_hdr.dst_addr.in6_u.u6_addr8 });
    let protocol_type = ProtocolType::Icmp;

    let snat_key = ConntrackKey::new(src_addr, dst_addr, 0, 0, protocol_type);
    match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            let snat_entry = ConntrackEntry::new(nic_ip, dst_addr, 0, 0, protocol_type);
            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, 0, 0, protocol_type);
            let dnat_entry = ConntrackEntry::new(dst_addr, src_addr, 0, 0, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv6_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv6 icmp redirect route insert conntrack failed");

                return Ok(TC_ACT_SHOT);
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, 0, 0, protocol_type);

            match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(
                        ctx,
                        "ipv6 icmp redirect route conntrack dnat miss, need rebuild"
                    );

                    let dnat_entry = ConntrackEntry::new(dst_addr, src_addr, 0, 0, protocol_type);

                    if ipv6_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv6 icmp redirect route insert conntrack dnat failed");

                        return Ok(TC_ACT_SHOT);
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    if ipv6::ipv6_snat(ctx, ipv6_hdr, L4Hdr::Icmp(icmp_hdr), Some(nic_ip), None).is_err() {
        error!(ctx, "ipv6 icmp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}
