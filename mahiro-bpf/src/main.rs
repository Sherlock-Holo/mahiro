#![no_std]
#![no_main]

use aya_bpf::bindings::xdp_action::XDP_PASS;
use aya_bpf::bindings::TC_ACT_SHOT;
use aya_bpf::macros::{classifier, xdp};
use aya_bpf::programs::{TcContext, XdpContext};
use mahiro_bpf::prog::nat::{egress, ingress};
use mahiro_bpf::prog::redirect_route;

#[classifier(name = "snat_egress")]
fn snat_egress(ctx: TcContext) -> i32 {
    egress::egress(ctx).unwrap_or(TC_ACT_SHOT)
}

#[classifier(name = "dnat_ingress")]
fn dnat_ingress(ctx: TcContext) -> i32 {
    ingress::ingress(ctx).unwrap_or(TC_ACT_SHOT)
}

#[xdp(name = "redirect_route")]
fn redirect_route(ctx: XdpContext) -> u32 {
    redirect_route::redirect_route(ctx).unwrap_or(XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
