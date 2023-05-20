use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::helpers::bpf_redirect;
use aya_bpf::programs::TcContext;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

use crate::context_ext::ContextExt;
use crate::route;

mod ipv4;
mod ipv6;

pub fn redirect_route(ctx: TcContext) -> Result<i32, ()> {
    let ipv4hdr = ctx.load_ptr::<Ipv4Hdr>(0).ok_or(())?;
    let egress_iface_index = if ipv4hdr.version() == 4 {
        let egress_iface_index = route::get_egress_iface_index_from_tun_ipv4(&ctx, ipv4hdr)?;
        let egress_iface_index = match egress_iface_index {
            None => return Ok(TC_ACT_OK),
            Some(egress_iface_index) => egress_iface_index,
        };

        if !ipv4::ipv4_redirect_route_snat(&ctx, egress_iface_index)? {
            return Ok(TC_ACT_OK);
        }

        egress_iface_index
    } else if ipv4hdr.version() == 6 {
        let ipv6hdr = ctx.load_ptr::<Ipv6Hdr>(0).ok_or(())?;

        let egress_iface_index = route::get_egress_iface_index_from_tun_ipv6(&ctx, ipv6hdr)?;
        let egress_iface_index = match egress_iface_index {
            None => return Ok(TC_ACT_OK),
            Some(egress_iface_index) => egress_iface_index,
        };

        if !ipv6::ipv6_redirect_route_snat(&ctx, egress_iface_index)? {
            return Ok(TC_ACT_OK);
        }

        egress_iface_index
    } else {
        return Ok(TC_ACT_OK);
    };

    unsafe { Ok(bpf_redirect(egress_iface_index, 0) as _) }
}
