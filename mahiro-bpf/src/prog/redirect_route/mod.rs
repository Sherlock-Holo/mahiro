use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::helpers::{bpf_redirect, bpf_skb_change_head};
use aya_bpf::programs::TcContext;
use aya_log_ebpf::{debug, error};
use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

use crate::context_ext::ContextExt;
use crate::route;

pub fn redirect_route(mut ctx: TcContext) -> Result<i32, ()> {
    let ipv4hdr = ctx.load_ptr::<Ipv4Hdr>(0).ok_or(())?;
    let egress_iface_index = if ipv4hdr.version() == 4 {
        match route::get_egress_iface_index_from_tun_ipv4(&ctx, ipv4hdr)? {
            None => return Ok(TC_ACT_OK),
            Some(egress_iface_index) => egress_iface_index,
        }
    } else if ipv4hdr.version() == 6 {
        let ipv6hdr = ctx.load_ptr::<Ipv6Hdr>(0).ok_or(())?;

        match route::get_egress_iface_index_from_tun_ipv6(&ctx, ipv6hdr)? {
            None => return Ok(TC_ACT_OK),
            Some(egress_iface_index) => egress_iface_index,
        }
    } else {
        return Ok(TC_ACT_OK);
    };

    unsafe {
        if bpf_skb_change_head(ctx.skb.skb, EthHdr::LEN as _, 0) < 0 {
            error!(&ctx, "change tun skb header failed");

            return Err(());
        }
    }

    debug!(&ctx, "change tun skb header done");

    ctx.store(0, &egress_iface_index.eth_header, 0)
        .map_err(|_| ())?;

    debug!(&ctx, "store eth header done");

    unsafe { Ok(bpf_redirect(egress_iface_index.index, 0) as _) }
}
