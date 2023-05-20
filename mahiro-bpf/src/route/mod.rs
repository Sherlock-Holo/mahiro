use core::ffi::c_long;
use core::mem::size_of_val;

use aya_bpf::bindings::{
    __be32, __u32, __u8, bpf_fib_lookup, bpf_fib_lookup__bindgen_ty_1,
    bpf_fib_lookup__bindgen_ty_2, bpf_fib_lookup__bindgen_ty_3, bpf_fib_lookup__bindgen_ty_4,
    BPF_FIB_LKUP_RET_SUCCESS, BPF_FIB_LOOKUP_DIRECT,
};
use aya_bpf::helpers::bpf_fib_lookup;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::{debug, error};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

const AF_INET: __u8 = 2;
const AF_INET6: __u8 = 10;
const IPV6_FLOWINFO_MASK: __be32 = 0x0FFFFFFFu32.to_be();

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EgressIfaceInfo {
    pub eth_header: EthHdr,
    pub index: __u32,
    _padding: [u8; 6],
}

pub fn get_egress_iface_index_from_tun_ipv4(
    ctx: &TcContext,
    ipv4hdr: &mut Ipv4Hdr,
) -> Result<Option<EgressIfaceInfo>, ()> {
    let mut fib_lookup = bpf_fib_lookup {
        family: AF_INET,
        l4_protocol: ipv4hdr.proto as _,
        sport: 0,
        dport: 0,
        __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1 {
            tot_len: u16::from_be(ipv4hdr.tot_len),
        },
        ifindex: unsafe { (*ctx.skb.skb).ingress_ifindex },
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
            ctx.skb.skb as _,
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

        return Ok(Some(EgressIfaceInfo {
            eth_header: EthHdr {
                dst_addr: fib_lookup.dmac,
                src_addr: fib_lookup.smac,
                ether_type: EtherType::Ipv4,
            },
            index: fib_lookup.ifindex,
            _padding: [0; 6],
        }));
    }

    debug!(ctx, "get ipv4 egress index result {}", result);

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

pub fn get_egress_iface_index_from_tun_ipv6(
    ctx: &TcContext,
    ipv6hdr: &mut Ipv6Hdr,
) -> Result<Option<EgressIfaceInfo>, ()> {
    let mut fib_lookup = unsafe {
        bpf_fib_lookup {
            family: AF_INET6,
            l4_protocol: ipv6hdr.next_hdr as _,
            sport: 0,
            dport: 0,
            __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1 {
                tot_len: u16::from_be(ipv6hdr.payload_len),
            },
            ifindex: (*ctx.skb.skb).ingress_ifindex,
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
            ctx.skb.skb as _,
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

        return Ok(Some(EgressIfaceInfo {
            eth_header: EthHdr {
                dst_addr: fib_lookup.dmac,
                src_addr: fib_lookup.smac,
                ether_type: EtherType::Ipv6,
            },
            index: fib_lookup.ifindex,
            _padding: [0; 6],
        }));
    }

    debug!(ctx, "get ipv6 egress index result {}", result);

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
