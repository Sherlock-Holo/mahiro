use aya_bpf::bindings::{BPF_F_NO_PREALLOC, TC_ACT_OK};
use aya_bpf::macros::map;
use aya_bpf::maps::{Array, LpmTrie};
use aya_bpf::programs::TcContext;
use network_types::eth::{EthHdr, EtherType};

use crate::context_ext::ContextExt;
use crate::ip_addr::{Ipv4Addr, Ipv6Addr};

mod ipv4;

const MAX_LOCAL_IP_RULE_SIZE: u32 = 65535;
const NIC_IP_MAP_SIZE: u32 = 128;

/// value 1 means is a mahiro network ip
#[map]
static IPV4_MAHIRO_IP: LpmTrie<Ipv4Addr, u8> =
    LpmTrie::with_max_entries(MAX_LOCAL_IP_RULE_SIZE, BPF_F_NO_PREALLOC);

/// mahiro network ipv4 prefix
#[map]
static IPV4_MAHIRO_PREFIX: Array<u8> = Array::with_max_entries(1, 0);

/// value 1 means is a mahiro ip
#[map]
static IPV6_MAHIRO_IP: LpmTrie<Ipv6Addr, u8> =
    LpmTrie::with_max_entries(MAX_LOCAL_IP_RULE_SIZE, BPF_F_NO_PREALLOC);

/// mahiro network ipv6 prefix
#[map]
static IPV6_MAHIRO_PREFIX: Array<u8> = Array::with_max_entries(1, 0);

pub fn egress(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr = ctx.load_ptr::<EthHdr>(0).ok_or(())?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => ipv4::ipv4_egress(&ctx, eth_hdr),
        EtherType::Ipv6 => {
            todo!()
        }

        _ => Ok(TC_ACT_OK),
    }
}
