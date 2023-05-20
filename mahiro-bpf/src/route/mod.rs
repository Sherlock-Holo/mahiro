use core::ffi::c_long;
use core::mem::size_of_val;

use aya_bpf::bindings::xdp_action::XDP_PASS;
use aya_bpf::bindings::{
    __be32, __u32, __u8, bpf_fib_lookup, bpf_fib_lookup__bindgen_ty_1,
    bpf_fib_lookup__bindgen_ty_2, bpf_fib_lookup__bindgen_ty_3, bpf_fib_lookup__bindgen_ty_4,
    BPF_FIB_LKUP_RET_SUCCESS, BPF_FIB_LOOKUP_DIRECT,
};
use aya_bpf::helpers::{bpf_fib_lookup, bpf_redirect};
use aya_bpf::programs::XdpContext;
use aya_log_ebpf::{debug, error};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

use crate::context_ext::ContextExt;

const AF_INET: __u8 = 1;
const AF_INET6: __u8 = 10;
const IPV6_FLOWINFO_MASK: __be32 = 0x0FFFFFFFu32.to_be();

pub fn redirect_route(ctx: XdpContext) -> Result<u32, ()> {
    let iface_index = get_egress_iface_index_from_tun(&ctx)?;
    match iface_index {
        None => Ok(XDP_PASS),
        Some(index) => unsafe { Ok(bpf_redirect(index, 0) as _) },
    }
}

fn get_egress_iface_index_from_tun(ctx: &XdpContext) -> Result<Option<__u32>, ()> {
    let ipv4hdr = ctx.load_ptr::<Ipv4Hdr>(0).ok_or(())?;

    if ipv4hdr.version() == 4 {
        get_egress_iface_index_from_tun_ipv4(ctx, ipv4hdr)
    } else if ipv4hdr.version() == 6 {
        // actually that is ipv6 packet, need use ipv6 hdr
        let ipv6hdr = ctx.load_ptr::<Ipv6Hdr>(0).ok_or(())?;

        get_egress_iface_index_from_tun_ipv6(ctx, ipv6hdr)
    } else {
        // unknown packet, let it go...
        Ok(None)
    }
}

fn get_egress_iface_index_from_tun_ipv4(
    ctx: &XdpContext,
    ipv4hdr: &mut Ipv4Hdr,
) -> Result<Option<__u32>, ()> {
    let mut fib_lookup = bpf_fib_lookup {
        family: AF_INET,
        l4_protocol: ipv4hdr.proto as _,
        sport: 0,
        dport: 0,
        __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1 {
            tot_len: u16::from_be(ipv4hdr.tot_len),
        },
        ifindex: unsafe { (*ctx.ctx).ingress_ifindex },
        __bindgen_anon_2: bpf_fib_lookup__bindgen_ty_2 { tos: ipv4hdr.tos },
        __bindgen_anon_3: bpf_fib_lookup__bindgen_ty_3 {
            ipv4_src: ipv4hdr.src_addr,
        },
        __bindgen_anon_4: bpf_fib_lookup__bindgen_ty_4 {
            ipv4_dst: ipv4hdr.dst_addr,
        },
        h_vlan_proto: 0,
        h_vlan_TCI: 0,
        smac: [0; 6],
        dmac: [0; 6],
    };

    let result = unsafe {
        bpf_fib_lookup(
            ctx.ctx as _,
            &mut fib_lookup as *mut _,
            size_of_val(&fib_lookup) as _,
            BPF_FIB_LOOKUP_DIRECT,
        )
    };

    if result < 0 {
        error!(ctx, "get ipv4 egress index failed, result {}", result);

        return Err(());
    }

    if result == BPF_FIB_LKUP_RET_SUCCESS as c_long {
        debug!(ctx, "get ipv4 egress index {} done", fib_lookup.ifindex);

        return Ok(Some(fib_lookup.ifindex));
    }

    // BPF_FIB_LKUP_RET_SUCCESS,      /* lookup successful */
    // BPF_FIB_LKUP_RET_BLACKHOLE,    /* dest is blackholed; can be dropped */
    // BPF_FIB_LKUP_RET_UNREACHABLE,  /* dest is unreachable; can be dropped */
    // BPF_FIB_LKUP_RET_PROHIBIT,     /* dest not allowed; can be dropped */
    // BPF_FIB_LKUP_RET_NOT_FWDED,    /* packet is not forwarded */
    // BPF_FIB_LKUP_RET_FWD_DISABLED, /* fwding is not enabled on ingress */
    // BPF_FIB_LKUP_RET_UNSUPP_LWT,   /* fwd requires encapsulation */
    // BPF_FIB_LKUP_RET_NO_NEIGH,     /* no neighbor entry for nh */
    // BPF_FIB_LKUP_RET_FRAG_NEEDED,  /* fragmentation required to fwd */
    //
    // but we don't care other
    Ok(None)
}

fn get_egress_iface_index_from_tun_ipv6(
    ctx: &XdpContext,
    ipv6hdr: &mut Ipv6Hdr,
) -> Result<Option<__u32>, ()> {
    let mut fib_lookup = unsafe {
        bpf_fib_lookup {
            family: AF_INET6,
            l4_protocol: ipv6hdr.next_hdr as _,
            sport: 0,
            dport: 0,
            __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1 {
                tot_len: u16::from_be(ipv6hdr.payload_len),
            },
            ifindex: (*ctx.ctx).ingress_ifindex,
            __bindgen_anon_2: bpf_fib_lookup__bindgen_ty_2 {
                flowinfo: *(ipv6hdr as *mut _ as *mut __be32) & IPV6_FLOWINFO_MASK,
            },
            __bindgen_anon_3: bpf_fib_lookup__bindgen_ty_3 {
                ipv6_src: ipv6hdr.src_addr.in6_u.u6_addr32,
            },
            __bindgen_anon_4: bpf_fib_lookup__bindgen_ty_4 {
                ipv6_dst: ipv6hdr.dst_addr.in6_u.u6_addr32,
            },
            h_vlan_proto: 0,
            h_vlan_TCI: 0,
            smac: [0; 6],
            dmac: [0; 6],
        }
    };

    let result = unsafe {
        bpf_fib_lookup(
            ctx.ctx as _,
            &mut fib_lookup as *mut _,
            size_of_val(&fib_lookup) as _,
            BPF_FIB_LOOKUP_DIRECT,
        )
    };

    if result < 0 {
        error!(ctx, "get ipv6 egress index failed, result {}", result);

        return Err(());
    }

    if result == BPF_FIB_LKUP_RET_SUCCESS as c_long {
        debug!(ctx, "get ipv6 egress index {} done", fib_lookup.ifindex);

        return Ok(Some(fib_lookup.ifindex));
    }

    // BPF_FIB_LKUP_RET_SUCCESS,      /* lookup successful */
    // BPF_FIB_LKUP_RET_BLACKHOLE,    /* dest is blackholed; can be dropped */
    // BPF_FIB_LKUP_RET_UNREACHABLE,  /* dest is unreachable; can be dropped */
    // BPF_FIB_LKUP_RET_PROHIBIT,     /* dest not allowed; can be dropped */
    // BPF_FIB_LKUP_RET_NOT_FWDED,    /* packet is not forwarded */
    // BPF_FIB_LKUP_RET_FWD_DISABLED, /* fwding is not enabled on ingress */
    // BPF_FIB_LKUP_RET_UNSUPP_LWT,   /* fwd requires encapsulation */
    // BPF_FIB_LKUP_RET_NO_NEIGH,     /* no neighbor entry for nh */
    // BPF_FIB_LKUP_RET_FRAG_NEEDED,  /* fragmentation required to fwd */
    //
    // but we don't care other
    Ok(None)
}
