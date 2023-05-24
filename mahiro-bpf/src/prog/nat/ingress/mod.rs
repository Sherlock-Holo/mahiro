use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::helpers::bpf_redirect;
use aya_bpf::programs::TcContext;
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

    unsafe { Ok(bpf_redirect(egress_iface_info.index, 0) as _) }
}
