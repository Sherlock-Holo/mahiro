use aya_bpf::bindings::BPF_F_NO_PREALLOC;
use aya_bpf::macros::map;
use aya_bpf::maps::{HashMap, LpmTrie};

use crate::ip_addr::{Ipv4Addr, Ipv6Addr};

const MAX_LOCAL_IP_RULE_SIZE: u32 = 65535;
const NIC_IP_MAP_SIZE: u32 = 128;

#[map]
pub static NIC_IPV4_MAP: HashMap<u32, Ipv4Addr> = HashMap::with_max_entries(NIC_IP_MAP_SIZE, 0);

/// value 1 means is a mahiro network ip
#[map]
pub static IPV4_MAHIRO_IP: LpmTrie<Ipv4Addr, u8> =
    LpmTrie::with_max_entries(MAX_LOCAL_IP_RULE_SIZE, BPF_F_NO_PREALLOC);

#[map]
pub static NIC_IPV6_MAP: HashMap<u32, Ipv6Addr> = HashMap::with_max_entries(NIC_IP_MAP_SIZE, 0);

/// value 1 means is a mahiro ip
#[map]
pub static IPV6_MAHIRO_IP: LpmTrie<Ipv6Addr, u8> =
    LpmTrie::with_max_entries(MAX_LOCAL_IP_RULE_SIZE, BPF_F_NO_PREALLOC);
