use aya_bpf::bindings::__be16;
use aya_bpf::helpers::bpf_ktime_get_boot_ns;
use aya_bpf::macros::map;
use aya_bpf::maps::LruHashMap;

use crate::ip_addr::Ipv4Addr;

use super::{ConntrackType, Error, ProtocolType, MAX_CONNTRACK_TABLE_SIZE};

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
    protocol_type: u32,
}

impl ConntrackKey {
    pub const fn new(
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        src_port: __be16,
        dst_port: __be16,
        protocol_type: ProtocolType,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol_type: protocol_type as _,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct ConntrackEntry {
    update_time: u64,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: __be16,
    dst_port: __be16,
    protocol_type: u32,
}

impl ConntrackEntry {
    pub fn new(
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        src_port: __be16,
        dst_port: __be16,
        protocol_type: ProtocolType,
    ) -> Self {
        let create_time = unsafe { bpf_ktime_get_boot_ns() };

        Self {
            update_time: create_time,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol_type: protocol_type as _,
        }
    }

    pub fn set_update_time(&mut self, update_time: u64) {
        self.update_time = update_time;
    }

    pub fn get_src_addr(&self) -> Ipv4Addr {
        self.src_addr
    }

    pub fn get_dst_addr(&self) -> Ipv4Addr {
        self.dst_addr
    }

    pub fn get_src_port(&self) -> __be16 {
        self.src_port
    }

    pub fn get_dst_port(&self) -> __be16 {
        self.dst_port
    }
}

#[derive(Debug, Clone)]
pub struct ConntrackPair<'a> {
    snat: (&'a ConntrackKey, &'a ConntrackEntry),
    dnat: (&'a ConntrackKey, &'a ConntrackEntry),
}

impl<'a> ConntrackPair<'a> {
    pub fn new(
        snat_key: &'a ConntrackKey,
        snat_entry: &'a ConntrackEntry,
        dnat_key: &'a ConntrackKey,
        dnat_entry: &'a ConntrackEntry,
    ) -> Self {
        Self {
            snat: (snat_key, snat_entry),
            dnat: (dnat_key, dnat_entry),
        }
    }
}

pub fn insert_conntrack_pair(conntrack_pair: ConntrackPair) -> Result<(), Error> {
    if SNAT_CONNTRACK_TABLE
        .insert(conntrack_pair.snat.0, conntrack_pair.snat.1, 0)
        .is_err()
    {
        return Err(Error::InsertConntrackError);
    }

    if DNAT_CONNTRACK_TABLE
        .insert(conntrack_pair.dnat.0, conntrack_pair.dnat.1, 0)
        .is_err()
    {
        return Err(Error::InsertConntrackError);
    }

    Ok(())
}

pub fn insert_conntrack(
    key: &ConntrackKey,
    value: &ConntrackEntry,
    conntrack_type: ConntrackType,
) -> Result<(), Error> {
    let conntrack_table = match conntrack_type {
        ConntrackType::Snat => &SNAT_CONNTRACK_TABLE,
        ConntrackType::Dnat => &DNAT_CONNTRACK_TABLE,
    };

    conntrack_table
        .insert(key, value, 0)
        .map_err(|_| Error::InsertConntrackError)
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

pub fn remove_conntrack_entry(
    key: &ConntrackKey,
    conntrack_type: ConntrackType,
) -> Result<(), Error> {
    let conntrack_table = match conntrack_type {
        ConntrackType::Snat => &SNAT_CONNTRACK_TABLE,
        ConntrackType::Dnat => &DNAT_CONNTRACK_TABLE,
    };

    conntrack_table
        .remove(key)
        .map_err(|_| Error::RemoveConntrackError)
}
