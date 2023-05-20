use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::programs::TcContext;
use network_types::eth::{EthHdr, EtherType};

use crate::context_ext::ContextExt;

mod ipv4;
mod ipv6;

pub fn egress(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr = ctx.load_ptr::<EthHdr>(0).ok_or(())?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => ipv4::ipv4_egress(&ctx, eth_hdr),
        EtherType::Ipv6 => ipv6::ipv6_egress(&ctx, eth_hdr),

        _ => Ok(TC_ACT_OK),
    }
}
