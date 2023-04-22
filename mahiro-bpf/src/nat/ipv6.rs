use core::mem::size_of;

use aya_bpf::bindings::{__be16, __be32, TC_ACT_OK};
use aya_bpf::bpf_printk;
use aya_bpf::helpers::bpf_csum_diff;
use aya_bpf::programs::TcContext;
use network_types::ip::Ipv6Hdr;

use crate::ip_addr::Ipv6Addr;

use super::{update_l4_csum, Error, IpAddrType, L4Hdr};

pub fn ipv6_dnat(
    ctx: TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    mut l4_hdr: L4Hdr,
    ip: Option<Ipv6Addr>,
    port: Option<__be16>,
) -> Result<i32, Error> {
    // ipv6 header doesn't have csum
    if let Some(ip) = ip {
        let new_ip: [u8; 16] = ip.into();

        ipv6_hdr.dst_addr.in6_u.u6_addr8 = new_ip;
    }

    let l4_csum_diff = match port {
        None => None,
        Some(port) => {
            let mut origin_port = match &l4_hdr {
                L4Hdr::Tcp(tcp_hdr) => tcp_hdr.dest as __be32,
                L4Hdr::Udp(udp_hdr) => udp_hdr.dest as __be32,
            };

            let mut new_port = port as __be32;

            let csum_diff = unsafe {
                let csum_diff = bpf_csum_diff(
                    &mut origin_port as *mut _,
                    size_of::<__be32>() as _,
                    &mut new_port as *mut _,
                    size_of::<__be32>() as _,
                    0,
                );
                if csum_diff < 0 {
                    return Err(Error::CsumDiffError);
                }

                csum_diff
            };

            match &mut l4_hdr {
                L4Hdr::Tcp(tcp_hdr) => {
                    tcp_hdr.dest = port;
                }
                L4Hdr::Udp(udp_hdr) => {
                    udp_hdr.dest = port;
                }
            }

            Some(csum_diff)
        }
    };

    if let Some(l4_csum_diff) = l4_csum_diff {
        update_l4_csum(&ctx, IpAddrType::V6, l4_csum_diff, l4_hdr)?;
    }

    unsafe {
        bpf_printk!(b"ipv6 dnat change done");
    }

    Ok(TC_ACT_OK)
}

pub fn ipv6_snat(
    ctx: TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    mut l4_hdr: L4Hdr,
    ip: Option<Ipv6Addr>,
    port: Option<__be16>,
) -> Result<i32, Error> {
    // ipv6 header doesn't have csum
    if let Some(ip) = ip {
        let new_ip: [u8; 16] = ip.into();

        ipv6_hdr.src_addr.in6_u.u6_addr8 = new_ip;
    }

    let l4_csum_diff = match port {
        None => None,
        Some(port) => {
            let mut origin_port = match &l4_hdr {
                L4Hdr::Tcp(tcp_hdr) => tcp_hdr.source as __be32,
                L4Hdr::Udp(udp_hdr) => udp_hdr.source as __be32,
            };

            let mut new_port = port as __be32;

            let csum_diff = unsafe {
                let csum_diff = bpf_csum_diff(
                    &mut origin_port as *mut _,
                    size_of::<__be32>() as _,
                    &mut new_port as *mut _,
                    size_of::<__be32>() as _,
                    0,
                );
                if csum_diff < 0 {
                    return Err(Error::CsumDiffError);
                }

                csum_diff
            };

            match &mut l4_hdr {
                L4Hdr::Tcp(tcp_hdr) => {
                    tcp_hdr.source = port;
                }
                L4Hdr::Udp(udp_hdr) => {
                    udp_hdr.source = port;
                }
            }

            Some(csum_diff)
        }
    };

    if let Some(l4_csum_diff) = l4_csum_diff {
        update_l4_csum(&ctx, IpAddrType::V6, l4_csum_diff, l4_hdr)?;
    }

    unsafe {
        bpf_printk!(b"ipv6 snat change done");
    }

    Ok(TC_ACT_OK)
}
