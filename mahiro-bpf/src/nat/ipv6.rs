use core::mem::size_of;

use aya_bpf::bindings::{__be16, __be32, __s64, TC_ACT_OK};
use aya_bpf::bpf_printk;
use aya_bpf::helpers::bpf_csum_diff;
use aya_bpf::programs::TcContext;
use network_types::ip::Ipv6Hdr;

use crate::ip_addr::Ipv6Addr;

use super::{update_l4_csum, Error, IpAddrType, L4Hdr};

pub fn ipv6_dnat(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    mut l4_hdr: L4Hdr,
    ip: Option<Ipv6Addr>,
    port: Option<__be16>,
) -> Result<i32, Error> {
    let l3_csum_diff = if let Some(ip) = ip {
        let mut new_ip: [u32; 4] = ip.into();
        let mut dst_ip = unsafe { ipv6_hdr.dst_addr.in6_u.u6_addr32 };

        ipv6_hdr.dst_addr.in6_u.u6_addr32 = new_ip;

        Some(calculate_ipv6_csum_diff(&mut dst_ip, &mut new_ip)?)
    } else {
        None
    };

    let l4_csum_diff = match port {
        None => None,
        Some(port) => {
            let mut origin_port = match &l4_hdr {
                L4Hdr::Tcp(tcp_hdr) => tcp_hdr.dest as __be32,
                L4Hdr::Udp(udp_hdr) => udp_hdr.dest as __be32,
            };

            let mut new_port = port as __be32;
            let l3_csum_diff = l3_csum_diff.unwrap_or(0);

            let csum_diff = unsafe {
                let csum_diff = bpf_csum_diff(
                    &mut origin_port as *mut _,
                    size_of::<__be32>() as _,
                    &mut new_port as *mut _,
                    size_of::<__be32>() as _,
                    l3_csum_diff as _,
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

    update_csum(ctx, l3_csum_diff, l4_csum_diff, l4_hdr)?;

    unsafe {
        bpf_printk!(b"ipv6 dnat change done");
    }

    Ok(TC_ACT_OK)
}

pub fn ipv6_snat(
    ctx: &TcContext,
    ipv6_hdr: &mut Ipv6Hdr,
    mut l4_hdr: L4Hdr,
    ip: Option<Ipv6Addr>,
    port: Option<__be16>,
) -> Result<i32, Error> {
    let l3_csum_diff = if let Some(ip) = ip {
        let mut new_ip: [u32; 4] = ip.into();
        let mut src_addr = unsafe { ipv6_hdr.src_addr.in6_u.u6_addr32 };

        ipv6_hdr.src_addr.in6_u.u6_addr32 = new_ip;

        Some(calculate_ipv6_csum_diff(&mut src_addr, &mut new_ip)?)
    } else {
        None
    };

    let l4_csum_diff = match port {
        None => None,
        Some(port) => {
            let mut origin_port = match &l4_hdr {
                L4Hdr::Tcp(tcp_hdr) => tcp_hdr.source as __be32,
                L4Hdr::Udp(udp_hdr) => udp_hdr.source as __be32,
            };

            let mut new_port = port as __be32;
            let l3_csum_diff = l3_csum_diff.unwrap_or(0);

            let csum_diff = unsafe {
                let csum_diff = bpf_csum_diff(
                    &mut origin_port as *mut _,
                    size_of::<__be32>() as _,
                    &mut new_port as *mut _,
                    size_of::<__be32>() as _,
                    l3_csum_diff as _,
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

    update_csum(ctx, l3_csum_diff, l4_csum_diff, l4_hdr)?;

    unsafe {
        bpf_printk!(b"ipv6 snat change done");
    }

    Ok(TC_ACT_OK)
}

fn update_csum(
    ctx: &TcContext,
    l3_csum_diff: Option<__s64>,
    l4_csum_diff: Option<__s64>,
    l4_hdr: L4Hdr,
) -> Result<(), Error> {
    match (l3_csum_diff, l4_csum_diff) {
        (Some(_l3_csum_diff), Some(l4_csum_diff)) => {
            update_l4_csum(ctx, IpAddrType::V6, l4_csum_diff, l4_hdr)?;
        }

        (None, Some(l4_csum_diff)) => {
            update_l4_csum(ctx, IpAddrType::V6, l4_csum_diff, l4_hdr)?;
        }

        (Some(l3_csum_diff), None) => {
            update_l4_csum(ctx, IpAddrType::V6, l3_csum_diff, l4_hdr)?;
        }

        _ => {}
    }

    Ok(())
}

fn calculate_ipv6_csum_diff(
    old_ip: &mut [__be32; 4],
    new_ip: &mut [__be32; 4],
) -> Result<__s64, Error> {
    unsafe {
        let csum_diff = bpf_csum_diff(
            old_ip.as_mut_ptr() as *mut _,
            16,
            new_ip.as_mut_ptr() as *mut _,
            16,
            0,
        );
        if csum_diff < 0 {
            return Err(Error::CsumDiffError);
        }

        Ok(csum_diff)
    }
}
