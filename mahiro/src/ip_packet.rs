use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::addr_of;

use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum IpLocation {
    Src,
    Dst,
}

pub fn get_packet_ip(packet: &[u8], location: IpLocation) -> Option<IpAddr> {
    let ip_ver = packet[0] >> 4;
    if ip_ver == 0b100 {
        let ipv4_hdr = packet.as_ptr().cast::<Ipv4Hdr>();
        // Safety: ip version is ipv4

        unsafe {
            match location {
                IpLocation::Src => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    addr_of!((*ipv4_hdr).src_addr).read_unaligned(),
                )))),
                IpLocation::Dst => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    addr_of!((*ipv4_hdr).dst_addr).read_unaligned(),
                )))),
            }
        }
    } else if ip_ver == 0b0110 {
        let ipv6_hdr = packet.as_ptr().cast::<Ipv6Hdr>();
        // Safety: ip version is ipv6
        unsafe {
            match location {
                IpLocation::Src => Some(IpAddr::V6(Ipv6Addr::from(
                    addr_of!((*ipv6_hdr).src_addr)
                        .read_unaligned()
                        .in6_u
                        .u6_addr8,
                ))),
                IpLocation::Dst => Some(IpAddr::V6(Ipv6Addr::from(
                    addr_of!((*ipv6_hdr).dst_addr)
                        .read_unaligned()
                        .in6_u
                        .u6_addr8,
                ))),
            }
        }
    } else {
        None
    }
}
