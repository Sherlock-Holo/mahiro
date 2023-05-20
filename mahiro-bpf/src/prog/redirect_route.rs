use aya_bpf::programs::XdpContext;

use crate::route;

pub fn redirect_route(ctx: XdpContext) -> Result<u32, ()> {
    route::redirect_route(ctx)
}
