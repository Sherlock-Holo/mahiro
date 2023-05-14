use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use futures_channel::mpsc::Sender;

use super::message::EncryptMessage;
use crate::public_key::PublicKey;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub sender: Sender<EncryptMessage>,
}

#[derive(Debug, Default)]
struct ConnectedPeersInner {
    peer_infos: DashMap<PublicKey, PeerInfo>,
    mahiro_ips: DashMap<IpAddr, Sender<EncryptMessage>>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectedPeers(Arc<ConnectedPeersInner>);

impl ConnectedPeers {
    pub fn add_peer_info(&self, cookie: Bytes, addr: SocketAddr, sender: Sender<EncryptMessage>) {
        self.0
            .peer_infos
            .insert(cookie.into(), PeerInfo { addr, sender });
    }

    pub fn add_mahiro_ip(&self, addr: IpAddr, sender: Sender<EncryptMessage>) {
        self.0.mahiro_ips.insert(addr, sender);
    }

    pub fn remove_peer(&self, cookie: &Bytes) {
        if let Some((_, sender)) = self.0.peer_infos.remove(cookie.as_ref()) {
            self.0
                .mahiro_ips
                .retain(|_, other_sender| !sender.sender.same_receiver(other_sender))
        }
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
            .and_then(|mut info| {
                if info.addr == addr {
                    None
                } else {
                    let old_addr = info.addr;
                    info.addr = addr;

                    Some(old_addr)
                }
            })
    }
}
