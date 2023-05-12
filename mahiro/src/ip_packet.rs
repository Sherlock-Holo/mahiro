use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum IpLocation {
    Src,
    Dst,
}

pub fn get_packet_ip(packet: &[u8], location: IpLocation) -> Option<IpAddr> {
    let ip_ver = packet[0] >> 4;
    if ip_ver == 0b100 {
        // Safety: ip version is ipv4
        let ipv4_hdr = unsafe { &*(packet.as_ptr() as *const Ipv4Hdr) };

        match location {
            IpLocation::Src => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_hdr.src_addr)))),
            IpLocation::Dst => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_hdr.dst_addr)))),
        }
    } else if ip_ver == 0b0110 {
        // Safety: ip version is ipv6
        unsafe {
            let ipv6_hdr = &*(packet.as_ptr() as *const Ipv6Hdr);

            match location {
                IpLocation::Src => {
                    Some(IpAddr::V6(Ipv6Addr::from(ipv6_hdr.src_addr.in6_u.u6_addr8)))
                }
                IpLocation::Dst => {
                    Some(IpAddr::V6(Ipv6Addr::from(ipv6_hdr.dst_addr.in6_u.u6_addr8)))
                }
            }
        }
    } else {
        None
    }
}
