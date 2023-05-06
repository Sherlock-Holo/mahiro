use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

pub fn get_packet_mahiro_ip(packet: &[u8]) -> Option<IpAddr> {
    let ip_ver = packet[0] >> 4;
    if ip_ver == 0b100 {
        // Safety: ip version is ipv4
        let ipv4_hdr = unsafe { &*(packet.as_ptr() as *const Ipv4Hdr) };

        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(ipv4_hdr.src_addr))))
    } else if ip_ver == 0b0110 {
        // Safety: ip version is ipv6
        unsafe {
            let ipv6_hdr = unsafe { &*(packet.as_ptr() as *const Ipv6Hdr) };

            Some(IpAddr::V6(Ipv6Addr::from(ipv6_hdr.src_addr.in6_u.u6_addr8)))
        }
    } else {
        None
    }
}
