use aya_bpf::bindings::bpf_adj_room_mode::BPF_ADJ_ROOM_MAC;
use aya_bpf::bindings::{__s32, BPF_CSUM_LEVEL_DEC, BPF_F_ADJ_ROOM_NO_CSUM_RESET, TC_ACT_OK};
use aya_bpf::helpers::{bpf_csum_level, bpf_redirect, bpf_skb_adjust_room};
use aya_bpf::programs::TcContext;
use aya_log_ebpf::error;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

use crate::context_ext::ContextExt;
use crate::route;

mod ipv4;
mod ipv6;

pub fn ingress(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr = ctx.load_ptr::<EthHdr>(0).ok_or(())?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => ipv4::ipv4_ingress(&ctx, eth_hdr),
        EtherType::Ipv6 => ipv6::ipv6_ingress(&ctx, eth_hdr),

        _ => Ok(TC_ACT_OK),
    }
}

pub fn ingress_with_redirect_route(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr = ctx.load_ptr::<EthHdr>(0).ok_or(())?;
    let egress_iface_info = match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            ipv4::ipv4_ingress(&ctx, eth_hdr)?;
            let ipv4_hdr = ctx.load_ptr::<Ipv4Hdr>(EthHdr::LEN).ok_or(())?;

            route::get_egress_iface_index_from_tun_ipv4(&ctx, ipv4_hdr)?
        }
        EtherType::Ipv6 => {
            ipv6::ipv6_ingress(&ctx, eth_hdr)?;
            let ipv6_hdr = ctx.load_ptr::<Ipv6Hdr>(EthHdr::LEN).ok_or(())?;

            route::get_egress_iface_index_from_tun_ipv6(&ctx, ipv6_hdr)?
        }

        _ => return Ok(TC_ACT_OK),
    };
    let egress_iface_info = match egress_iface_info {
        None => return Ok(TC_ACT_OK),
        Some(egress_iface_info) => egress_iface_info,
    };

    unsafe {
        if bpf_skb_adjust_room(
            ctx.skb.skb,
            -(EthHdr::LEN as __s32),
            BPF_ADJ_ROOM_MAC,
            BPF_F_ADJ_ROOM_NO_CSUM_RESET as _,
        ) > 0
        {
            error!(&ctx, "remove eth header failed");

            return Err(());
        }

        if bpf_csum_level(ctx.skb.skb, BPF_CSUM_LEVEL_DEC as _) < 0 {
            error!(&ctx, "change csum level failed");

            return Err(());
        }

        Ok(bpf_redirect(egress_iface_info.index, 0) as _)
    }
}
