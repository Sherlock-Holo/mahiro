use aya_bpf::bindings::{__s64, BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR};
use aya_bpf::helpers::{bpf_l3_csum_replace, bpf_l4_csum_replace};
use aya_bpf::programs::TcContext;
use memoffset::offset_of;
use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub mod ipv4;
pub mod ipv6;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Error {
    CsumDiffError,
    CsumUpdateError,
}

pub enum L4Hdr<'a> {
    Tcp(&'a mut TcpHdr),
    Udp(&'a mut UdpHdr),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum IpAddrType {
    V4,
    V6,
}

fn update_l3_csum(ctx: &TcContext, csum_diff: __s64) -> Result<(), Error> {
    unsafe {
        if bpf_l3_csum_replace(
            ctx.skb.skb,
            (EthHdr::LEN + offset_of!(Ipv4Hdr, check)) as _,
            0,
            csum_diff as _,
            0,
        ) < 0
        {
            return Err(Error::CsumUpdateError);
        }
    }

    Ok(())
}

fn update_l4_csum(
    ctx: &TcContext,
    ip_addr_type: IpAddrType,
    csum_diff: __s64,
    l4_hdr: L4Hdr,
) -> Result<(), Error> {
    let mut flags = BPF_F_PSEUDO_HDR;

    let mut offset = match ip_addr_type {
        IpAddrType::V4 => EthHdr::LEN + Ipv4Hdr::LEN,
        IpAddrType::V6 => EthHdr::LEN + Ipv6Hdr::LEN,
    };

    offset = match l4_hdr {
        L4Hdr::Tcp(_) => offset + offset_of!(TcpHdr, check),
        L4Hdr::Udp(_) => {
            flags |= BPF_F_MARK_MANGLED_0;

            offset + offset_of!(UdpHdr, check)
        }
    };

    unsafe {
        if bpf_l4_csum_replace(ctx.skb.skb, offset as _, 0, csum_diff as _, flags as _) < 0 {
            return Err(Error::CsumUpdateError);
        }
    }

    Ok(())
}
