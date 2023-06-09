use core::mem::size_of;

use aya_bpf::bindings::{__be16, __be32, __s64, TC_ACT_OK};
use aya_bpf::helpers::bpf_csum_diff;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::debug;
use network_types::ip::Ipv4Hdr;

use super::{update_l3_csum, update_l4_csum, Error, IpAddrType, L4Hdr};
use crate::ip_addr::Ipv4Addr;

pub fn ipv4_dnat(
    ctx: &TcContext,
    ipv4_hdr: &mut Ipv4Hdr,
    mut l4_hdr: L4Hdr,
    ip: Option<Ipv4Addr>,
    port: Option<__be16>,
) -> Result<i32, Error> {
    let l3_csum_diff = match ip {
        None => None,
        Some(ip) => {
            let mut new_ip: __be32 = ip.into();

            let csum_diff = unsafe {
                let csum_diff = bpf_csum_diff(
                    &mut ipv4_hdr.dst_addr as *mut _,
                    size_of::<__be32>() as _,
                    &mut new_ip as *mut _,
                    size_of::<__be32>() as _,
                    0,
                );
                if csum_diff < 0 {
                    return Err(Error::CsumDiffError);
                }

                csum_diff
            };

            ipv4_hdr.dst_addr = new_ip;

            Some(csum_diff)
        }
    };

    let l4_csum_diff = match port {
        None => None,
        Some(port) => {
            try {
                let mut origin_port = match &l4_hdr {
                    L4Hdr::Tcp(tcp_hdr) => tcp_hdr.dest as __be32,
                    L4Hdr::Udp(udp_hdr) => udp_hdr.dest as __be32,
                    L4Hdr::Icmp(_) => None?,
                };

                let mut new_port = port as __be32;

                // if l3 has changed, calculate l4 header csum diff need ip csum diff
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
                    L4Hdr::Icmp(_) => {}
                }

                csum_diff
            }
        }
    };

    update_csum(ctx, l3_csum_diff, l4_csum_diff, l4_hdr)?;

    debug!(ctx, "ipv4 dnat change done");

    Ok(TC_ACT_OK)
}

pub fn ipv4_snat(
    ctx: &TcContext,
    ipv4_hdr: &mut Ipv4Hdr,
    mut l4_hdr: L4Hdr,
    ip: Option<Ipv4Addr>,
    port: Option<__be16>,
) -> Result<i32, Error> {
    let l3_csum_diff = match ip {
        None => None,
        Some(ip) => {
            let mut new_ip: __be32 = ip.into();

            let csum_diff = unsafe {
                let csum_diff = bpf_csum_diff(
                    &mut ipv4_hdr.src_addr as *mut _,
                    size_of::<__be32>() as _,
                    &mut new_ip as *mut _,
                    size_of::<__be32>() as _,
                    0,
                );
                if csum_diff < 0 {
                    return Err(Error::CsumDiffError);
                }

                csum_diff
            };

            ipv4_hdr.src_addr = new_ip;

            Some(csum_diff)
        }
    };

    let l4_csum_diff = match port {
        None => None,
        Some(port) => {
            try {
                let mut origin_port = match &l4_hdr {
                    L4Hdr::Tcp(tcp_hdr) => tcp_hdr.source as __be32,
                    L4Hdr::Udp(udp_hdr) => udp_hdr.source as __be32,
                    L4Hdr::Icmp(_) => None?,
                };

                let mut new_port = port as __be32;

                // if l3 has changed, calculate l4 header csum diff need ip csum diff
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
                    L4Hdr::Icmp(_) => {}
                }

                csum_diff
            }
        }
    };

    update_csum(ctx, l3_csum_diff, l4_csum_diff, l4_hdr)?;

    debug!(ctx, "ipv4 snat change done");

    Ok(TC_ACT_OK)
}

fn update_csum(
    ctx: &TcContext,
    l3_csum_diff: Option<__s64>,
    l4_csum_diff: Option<__s64>,
    l4_hdr: L4Hdr,
) -> Result<(), Error> {
    match (l3_csum_diff, l4_csum_diff) {
        (Some(l3_csum_diff), Some(l4_csum_diff)) => {
            update_l3_csum(ctx, l3_csum_diff)?;
            update_l4_csum(ctx, IpAddrType::V4, l4_csum_diff, l4_hdr)?;
        }

        (None, Some(l4_csum_diff)) => {
            update_l4_csum(ctx, IpAddrType::V4, l4_csum_diff, l4_hdr)?;
        }

        (Some(l3_csum_diff), None) => {
            update_l3_csum(ctx, l3_csum_diff)?;
            update_l4_csum(ctx, IpAddrType::V4, l3_csum_diff, l4_hdr)?;
        }

        _ => {}
    }

    Ok(())
}
