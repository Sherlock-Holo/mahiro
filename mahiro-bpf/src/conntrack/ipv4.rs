use aya_bpf::bindings::__be16;
use aya_bpf::helpers::bpf_ktime_get_boot_ns;
use aya_bpf::macros::map;
use aya_bpf::maps::LruHashMap;

use crate::ip_addr::Ipv4Addr;

use super::{ConntrackType, Error, MAX_CONNTRACK_TABLE_SIZE};

#[map]
static SNAT_CONNTRACK_TABLE: LruHashMap<ConntrackKey, ConntrackEntry> =
    LruHashMap::with_max_entries(MAX_CONNTRACK_TABLE_SIZE, 0);

#[map]
static DNAT_CONNTRACK_TABLE: LruHashMap<ConntrackKey, ConntrackEntry> =
    LruHashMap::with_max_entries(MAX_CONNTRACK_TABLE_SIZE, 0);

#[derive(Debug, Eq, PartialEq, Clone)]
#[repr(C)]
pub struct ConntrackKey {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: __be16,
    dst_port: __be16,
}

impl ConntrackKey {
    pub const fn new(
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        src_port: __be16,
        dst_port: __be16,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        }
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct ConntrackEntry {
    update_time: u64,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: __be16,
    dst_port: __be16,
    _padding: u32,
}

impl ConntrackEntry {
    pub fn new(src_addr: Ipv4Addr, dst_addr: Ipv4Addr, src_port: __be16, dst_port: __be16) -> Self {
        let create_time = unsafe { bpf_ktime_get_boot_ns() };

        Self {
            update_time: create_time,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            _padding: 0,
        }
    }

    pub fn set_update_time(&mut self, update_time: u64) {
        self.update_time = update_time;
    }
}

#[derive(Debug, Clone)]
pub struct ConntrackPair<'a> {
    origin: (&'a ConntrackKey, &'a ConntrackEntry),
    after: (&'a ConntrackKey, &'a ConntrackEntry),
}

pub fn insert_conntrack(conntrack_pair: ConntrackPair) -> Result<(), Error> {
    if SNAT_CONNTRACK_TABLE
        .insert(conntrack_pair.origin.0, conntrack_pair.origin.1, 0)
        .is_err()
    {
        return Err(Error::InsertConntrackError);
    }

    if DNAT_CONNTRACK_TABLE
        .insert(conntrack_pair.after.0, conntrack_pair.after.1, 0)
        .is_err()
    {
        return Err(Error::InsertConntrackError);
    }

    Ok(())
}

pub fn get_conntrack_entry(
    key: &ConntrackKey,
    conntrack_type: ConntrackType,
) -> Option<&mut ConntrackEntry> {
    let conntrack_table = match conntrack_type {
        ConntrackType::Snat => &SNAT_CONNTRACK_TABLE,
        ConntrackType::Dnat => &DNAT_CONNTRACK_TABLE,
    };

    conntrack_table
        .get_ptr_mut(key)
        .map(|entry| unsafe { &mut *entry })
}