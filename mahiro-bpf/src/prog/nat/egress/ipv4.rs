use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::helpers::bpf_ktime_get_boot_ns;
use aya_bpf::maps::lpm_trie::Key;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::{debug, error, warn};
use network_types::eth::EthHdr;
use network_types::icmp::IcmpHdr;
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::conntrack::ipv4::{ConntrackEntry, ConntrackKey, ConntrackPair};
use crate::conntrack::{ipv4 as ipv4_conntrack, ConntrackType, ProtocolType};
use crate::context_ext::ContextExt;
use crate::ip_addr::Ipv4Addr;
use crate::map::{IPV4_MAHIRO_IP, NIC_IPV4_MAP};
use crate::nat::{ipv4, L4Hdr};

pub fn ipv4_egress(ctx: &TcContext, _eth_hdr: &mut EthHdr) -> Result<i32, ()> {
    let ipv4_hdr = ctx.load_ptr::<Ipv4Hdr>(EthHdr::LEN).ok_or(())?;
    let src_addr = Ipv4Addr::from(ipv4_hdr.src_addr);
    let key = Key::new(32, src_addr);

    // the src ipv4 is not in mahiro network
    if IPV4_MAHIRO_IP.get(&key).copied().unwrap_or(0) == 0 {
        return Ok(TC_ACT_OK);
    }

    let egress_nic_index = unsafe { (*ctx.skb.skb).ifindex };
    let nic_ip = unsafe {
        match NIC_IPV4_MAP.get(&egress_nic_index).copied() {
            None => {
                error!(ctx, "egress nic index {} has no ipv4", egress_nic_index);

                return Ok(TC_ACT_SHOT);
            }
            Some(nic_index) => nic_index,
        }
    };

    match ipv4_hdr.proto {
        IpProto::Tcp => ipv4_tcp_egress(ctx, ipv4_hdr, nic_ip),
        IpProto::Udp => ipv4_udp_egress(ctx, ipv4_hdr, nic_ip),
        IpProto::Icmp => ipv4_icmp_egress(ctx, ipv4_hdr, nic_ip),

        _ => Ok(TC_ACT_OK),
    }
}

fn ipv4_tcp_egress(ctx: &TcContext, ipv4_hdr: &mut Ipv4Hdr, nic_ip: Ipv4Addr) -> Result<i32, ()> {
    let tcp_hdr = ctx
        .load_ptr::<TcpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(())?;

    let src_addr = Ipv4Addr::from(ipv4_hdr.src_addr);
    let dst_addr = Ipv4Addr::from(ipv4_hdr.dst_addr);
    let src_port = tcp_hdr.source;
    let dst_port = tcp_hdr.dest;
    let protocol_type = ProtocolType::Tcp;

    let snat_key = ConntrackKey::new(src_addr, dst_addr, src_port, dst_port, protocol_type);
    match ipv4_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
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

            if ipv4_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv4 tcp egress insert conntrack failed");

                return Ok(TC_ACT_SHOT);
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, dst_port, src_port, protocol_type);

            match ipv4_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(ctx, "ipv4 tcp egress conntrack dnat miss, need rebuild");

                    let dnat_entry =
                        ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);

                    if ipv4_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv4 tcp egress insert conntrack dnat failed");

                        return Ok(TC_ACT_SHOT);
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    if ipv4::ipv4_snat(ctx, ipv4_hdr, L4Hdr::Tcp(tcp_hdr), Some(nic_ip), None).is_err() {
        error!(ctx, "ipv4 tcp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}

fn ipv4_udp_egress(ctx: &TcContext, ipv4_hdr: &mut Ipv4Hdr, nic_ip: Ipv4Addr) -> Result<i32, ()> {
    let udp_hdr = ctx
        .load_ptr::<UdpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(())?;

    let src_addr = Ipv4Addr::from(ipv4_hdr.src_addr);
    let dst_addr = Ipv4Addr::from(ipv4_hdr.dst_addr);
    let src_port = udp_hdr.source;
    let dst_port = udp_hdr.dest;
    let protocol_type = ProtocolType::Udp;

    let snat_key = ConntrackKey::new(src_addr, dst_addr, src_port, dst_port, protocol_type);
    match ipv4_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            let snat_entry =
                ConntrackEntry::new(nic_ip, dst_addr, src_port, dst_port, protocol_type);
            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, dst_port, src_port, protocol_type);
            let dnat_entry =
                ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv4_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv4 udp egress insert conntrack failed");

                return Ok(TC_ACT_SHOT);
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, dst_port, src_port, protocol_type);

            match ipv4_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(ctx, "ipv4 udp egress conntrack dnat miss, need rebuild");

                    let dnat_entry =
                        ConntrackEntry::new(dst_addr, src_addr, dst_port, src_port, protocol_type);

                    if ipv4_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv4 udp egress insert conntrack dnat failed");

                        return Ok(TC_ACT_SHOT);
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    if ipv4::ipv4_snat(ctx, ipv4_hdr, L4Hdr::Udp(udp_hdr), Some(nic_ip), None).is_err() {
        error!(ctx, "ipv4 udp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}

fn ipv4_icmp_egress(ctx: &TcContext, ipv4_hdr: &mut Ipv4Hdr, nic_ip: Ipv4Addr) -> Result<i32, ()> {
    let icmp_hdr = ctx
        .load_ptr::<IcmpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(())?;

    let src_addr = Ipv4Addr::from(ipv4_hdr.src_addr);
    let dst_addr = Ipv4Addr::from(ipv4_hdr.dst_addr);
    let protocol_type = ProtocolType::Icmp;

    let snat_key = ConntrackKey::new(src_addr, dst_addr, 0, 0, protocol_type);
    match ipv4_conntrack::get_conntrack_entry(&snat_key, ConntrackType::Snat) {
        None => {
            let snat_entry = ConntrackEntry::new(nic_ip, dst_addr, 0, 0, protocol_type);
            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, 0, 0, protocol_type);
            let dnat_entry = ConntrackEntry::new(dst_addr, src_addr, 0, 0, protocol_type);
            let pair = ConntrackPair::new(&snat_key, &snat_entry, &dnat_key, &dnat_entry);

            if ipv4_conntrack::insert_conntrack_pair(pair).is_err() {
                error!(ctx, "ipv4 icmp egress insert conntrack failed");

                return Ok(TC_ACT_SHOT);
            }
        }

        Some(snat_entry) => {
            let update_time = unsafe { bpf_ktime_get_boot_ns() };
            snat_entry.set_update_time(update_time);

            let dnat_key = ConntrackKey::new(dst_addr, nic_ip, 0, 0, protocol_type);

            match ipv4_conntrack::get_conntrack_entry(&dnat_key, ConntrackType::Dnat) {
                None => {
                    warn!(ctx, "ipv4 icmp egress conntrack dnat miss, need rebuild");

                    let dnat_entry = ConntrackEntry::new(dst_addr, src_addr, 0, 0, protocol_type);

                    if ipv4_conntrack::insert_conntrack(&dnat_key, &dnat_entry, ConntrackType::Dnat)
                        .is_err()
                    {
                        error!(ctx, "ipv4 icmp egress insert conntrack dnat failed");

                        return Ok(TC_ACT_SHOT);
                    }
                }

                Some(dnat_entry) => {
                    dnat_entry.set_update_time(update_time);
                }
            }
        }
    }

    if ipv4::ipv4_snat(ctx, ipv4_hdr, L4Hdr::Icmp(icmp_hdr), Some(nic_ip), None).is_err() {
        error!(ctx, "ipv4 icmp snat failed");

        return Err(());
    }

    Ok(TC_ACT_OK)
}
