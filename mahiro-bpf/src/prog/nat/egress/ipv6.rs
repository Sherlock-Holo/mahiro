use core::ptr;

use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::helpers::bpf_ktime_get_boot_ns;
use aya_bpf::macros::map;
use aya_bpf::maps::lpm_trie::Key;
use aya_bpf::maps::PerCpuArray;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::{debug, error, warn};
use network_types::eth::EthHdr;
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

#[map(name = "IPV6_EGRESS_DST_HEAP")]
static IPV6_EGRESS_DST_HEAP: PerCpuArray<Ipv6Addr> = PerCpuArray::with_max_entries(1, 0);

pub fn ipv6_egress(ctx: &TcContext, _eth_hdr: &mut EthHdr) -> Result<i32, ()> {
    let ipv6_hdr = ctx.load_ptr::<Ipv6Hdr>(EthHdr::LEN).ok_or(())?;
    let src_addr = Ipv6Addr::from(unsafe { ipv6_hdr.src_addr.in6_u.u6_addr8 });
    let key = Key::new(128, src_addr);

    // the src ipv6 is not in mahiro network
    if IPV6_MAHIRO_IP.get(&key).copied().unwrap_or(0) == 0 {
        return Ok(TC_ACT_OK);
    }

    let egress_nic_index = unsafe { (*ctx.skb.skb).ifindex };
    let nic_ip = unsafe {
        match NIC_IPV6_MAP.get(&egress_nic_index) {
            None => {
                error!(ctx, "egress nic index {} has no ipv6", egress_nic_index);

                return Ok(TC_ACT_SHOT);
            }
            Some(nic_index) => nic_index,
        }
    };

    let dst_addr = IPV6_EGRESS_DST_HEAP.get_ptr_mut(0).ok_or(())?;
    let dst_addr = unsafe {
        ptr::copy_nonoverlapping(
            ipv6_hdr.dst_addr.in6_u.u6_addr8.as_ptr() as *const _,
            dst_addr,
            1,
        );

        &*dst_addr
    };

    match ipv6_hdr.next_hdr {
        IpProto::Tcp => ipv6_tcp_egress(ctx, ipv6_hdr, &src_addr, dst_addr, nic_ip),
        IpProto::Udp => ipv6_udp_egress(ctx, ipv6_hdr, &src_addr, dst_addr, nic_ip),
        IpProto::Ipv6Icmp => ipv6_icmp_egress(ctx, ipv6_hdr, &src_addr, dst_addr, nic_ip),
        _ => Ok(TC_ACT_OK),
    }
}

fn ipv6_tcp_egress(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    nic_ip: &Ipv6Addr,
) -> Result<i32, ()> {
    let tcp_hdr = match ctx.load_ptr::<TcpHdr>(EthHdr::LEN + Ipv6Hdr::LEN) {
        None => return Ok(TC_ACT_OK),
        Some(tcp_hdr) => tcp_hdr,
    };

    let src_port = tcp_hdr.source;
    let dst_port = tcp_hdr.dest;

    if check_tcp_conntrack(ctx, tcp_hdr, src_addr, dst_addr, nic_ip, src_port, dst_port).is_err() {
        return Ok(TC_ACT_SHOT);
    }

    if ipv6::ipv6_snat(ctx, ipv6_hdr, L4Hdr::Tcp(tcp_hdr), Some(*nic_ip), None).is_err() {
        error!(ctx, "ipv6 tcp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}

fn check_tcp_conntrack(
    ctx: &TcContext,
    tcp_hdr: &TcpHdr,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    nic_ip: &Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<(), ()> {
    let protocol_type = ProtocolType::Tcp;

    let snat_key = ConntrackKey::new(*src_addr, *dst_addr, src_port, dst_port, protocol_type);
    match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            // tcp packet is not SYN
            if tcp_hdr.syn() == 0 || tcp_hdr.ack() > 0 {
                debug!(ctx, "drop invalid tcp packet");

                return Err(());
            }

            let snat_entry =
                ConntrackEntry::new(*nic_ip, *dst_addr, src_port, dst_port, protocol_type);
            let dnat_key = ConntrackKey::new(*dst_addr, *nic_ip, dst_port, src_port, protocol_type);
            let dnat_entry =
                ConntrackEntry::new(*dst_addr, *src_addr, dst_port, src_port, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv6_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv6 tcp egress insert conntrack failed");

                return Err(());
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(*dst_addr, *nic_ip, dst_port, src_port, protocol_type);

            match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(ctx, "ipv6 tcp egress conntrack dnat miss, need rebuild");

                    let dnat_entry = ConntrackEntry::new(
                        *dst_addr,
                        *src_addr,
                        dst_port,
                        src_port,
                        protocol_type,
                    );

                    if ipv6_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv6 tcp egress insert conntrack dnat failed");

                        return Err(());
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    Ok(())
}

fn ipv6_udp_egress(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    nic_ip: &Ipv6Addr,
) -> Result<i32, ()> {
    let udp_hdr = match ctx.load_ptr::<UdpHdr>(EthHdr::LEN + Ipv6Hdr::LEN) {
        None => return Ok(TC_ACT_OK),
        Some(udp_hdr) => udp_hdr,
    };

    let src_port = udp_hdr.source;
    let dst_port = udp_hdr.dest;

    if check_udp_conntrack(ctx, src_addr, dst_addr, nic_ip, src_port, dst_port).is_err() {
        return Ok(TC_ACT_SHOT);
    }

    if ipv6::ipv6_snat(ctx, ipv6_hdr, L4Hdr::Udp(udp_hdr), Some(*nic_ip), None).is_err() {
        error!(ctx, "ipv6 udp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}

fn check_udp_conntrack(
    ctx: &TcContext,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    nic_ip: &Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<(), ()> {
    let protocol_type = ProtocolType::Udp;

    let snat_key = ConntrackKey::new(*src_addr, *dst_addr, src_port, dst_port, protocol_type);
    match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            let snat_entry =
                ConntrackEntry::new(*nic_ip, *dst_addr, src_port, dst_port, protocol_type);
            let dnat_key = ConntrackKey::new(*dst_addr, *nic_ip, dst_port, src_port, protocol_type);
            let dnat_entry =
                ConntrackEntry::new(*dst_addr, *src_addr, dst_port, src_port, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv6_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv6 udp egress insert conntrack failed");

                return Err(());
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(*dst_addr, *nic_ip, dst_port, src_port, protocol_type);

            match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(ctx, "ipv6 udp egress conntrack dnat miss, need rebuild");

                    let dnat_entry = ConntrackEntry::new(
                        *dst_addr,
                        *src_addr,
                        dst_port,
                        src_port,
                        protocol_type,
                    );

                    if ipv6_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv6 udp egress insert conntrack dnat failed");

                        return Err(());
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    Ok(())
}

fn ipv6_icmp_egress(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    nic_ip: &Ipv6Addr,
) -> Result<i32, ()> {
    let icmp_hdr = match ctx.load_ptr::<IcmpHdr>(EthHdr::LEN + Ipv6Hdr::LEN) {
        None => return Ok(TC_ACT_OK),
        Some(icmp_hdr) => icmp_hdr,
    };

    if check_icmp_conntrack(ctx, src_addr, dst_addr, nic_ip).is_err() {
        return Ok(TC_ACT_SHOT);
    }

    if ipv6::ipv6_snat(ctx, ipv6_hdr, L4Hdr::Icmp(icmp_hdr), Some(*nic_ip), None).is_err() {
        error!(ctx, "ipv6 icmp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}

fn check_icmp_conntrack(
    ctx: &TcContext,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    nic_ip: &Ipv6Addr,
) -> Result<(), ()> {
    let protocol_type = ProtocolType::Icmp;

    let snat_key = ConntrackKey::new(*src_addr, *dst_addr, 0, 0, protocol_type);
    match ipv6_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            let snat_entry = ConntrackEntry::new(*nic_ip, *dst_addr, 0, 0, protocol_type);
            let dnat_key = ConntrackKey::new(*dst_addr, *nic_ip, 0, 0, protocol_type);
            let dnat_entry = ConntrackEntry::new(*dst_addr, *src_addr, 0, 0, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv6_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv6 icmp egress insert conntrack failed");

                return Err(());
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(*dst_addr, *nic_ip, 0, 0, protocol_type);

            match ipv6_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(ctx, "ipv6 icmp egress conntrack dnat miss, need rebuild");

                    let dnat_entry = ConntrackEntry::new(*dst_addr, *src_addr, 0, 0, protocol_type);

                    if ipv6_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv6 icmp egress insert conntrack dnat failed");

                        return Err(());
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    Ok(())
}
