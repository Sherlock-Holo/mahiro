use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use flume::Sender;

use super::message::EncryptMessage;
use crate::public_key::PublicKey;

type Cookie = PublicKey;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub v4_addr: Option<SocketAddrV4>,
    pub v6_addr: Option<SocketAddrV6>,
    pub sender: Sender<EncryptMessage>,
}

#[derive(Debug)]
struct PeetStoreInner {
    static_peer_mahiro_ips: HashMap<PublicKey, (Ipv4Addr, Ipv6Addr)>,
    peer_infos: DashMap<Cookie, PeerInfo>,
    mahiro_ips: DashMap<IpAddr, Sender<EncryptMessage>>,
}

#[derive(Debug, Clone)]
pub struct PeerStore(Arc<PeetStoreInner>);

impl PeerStore {
    pub fn add_peer_info(&self, cookie: Bytes, addr: SocketAddr, sender: Sender<EncryptMessage>) {
        let peer_info = match addr {
            SocketAddr::V4(addr) => PeerInfo {
                v4_addr: Some(addr),
                v6_addr: None,
                sender,
            },
            SocketAddr::V6(addr) => PeerInfo {
                v4_addr: None,
                v6_addr: Some(addr),
                sender,
            },
        };

        self.0.peer_infos.insert(cookie.into(), peer_info);
    }

    pub fn add_mahiro_ip(&self, addr: IpAddr, sender: Sender<EncryptMessage>) {
        self.0.mahiro_ips.insert(addr, sender);
    }

    pub fn remove_peer(&self, cookie: &Bytes) {
        if let Some((_, sender)) = self.0.peer_infos.remove(cookie.as_ref()) {
            self.0
                .mahiro_ips
                .retain(|_, other_sender| !sender.sender.same_channel(other_sender))
        }
    }

    pub fn get_mahiro_ip_by_public_key(&self, public_key: &[u8]) -> Option<(Ipv4Addr, Ipv6Addr)> {
        self.0.static_peer_mahiro_ips.get(public_key).copied()
    }

    pub fn get_peer_info_by_cookie(&self, cookie: &Bytes) -> Option<PeerInfo> {
        self.0
            .peer_infos
            .get(cookie.as_ref())
            .map(|info| info.clone())
    }

    pub fn get_sender_by_mahiro_ip(&self, addr: IpAddr) -> Option<Sender<EncryptMessage>> {
        self.0.mahiro_ips.get(&addr).map(|sender| sender.clone())
    }

    pub fn update_peer_addr(&self, cookie: &Bytes, addr: SocketAddr) -> Option<SocketAddr> {
        self.0
            .peer_infos
            .get_mut(cookie.as_ref())
            .and_then(|mut info| match addr {
                SocketAddr::V4(addr) => {
                    if info.v4_addr == Some(addr) {
                        None
                    } else {
                        info.v4_addr.replace(addr).map(SocketAddr::V4)
                    }
                }
                SocketAddr::V6(addr) => {
                    if info.v6_addr == Some(addr) {
                        None
                    } else {
                        info.v6_addr.replace(addr).map(SocketAddr::V6)
                    }
                }
            })
    }
}

impl<I: IntoIterator<Item = (PublicKey, (Ipv4Addr, Ipv6Addr))>> From<I> for PeerStore {
    fn from(value: I) -> Self {
        Self(Arc::new(PeetStoreInner {
            static_peer_mahiro_ips: value.into_iter().collect(),
            peer_infos: Default::default(),
            mahiro_ips: Default::default(),
        }))
    }
}
