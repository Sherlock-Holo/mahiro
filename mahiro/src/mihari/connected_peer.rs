use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use dashmap::DashMap;
use futures_channel::mpsc::Sender;

use super::message::EncryptMessage;

#[derive(Debug, Default)]
struct ConnectedPeersInner {
    udp_addrs: DashMap<SocketAddr, Sender<EncryptMessage>>,
    mahiro_ips: DashMap<IpAddr, Sender<EncryptMessage>>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectedPeers(Arc<ConnectedPeersInner>);

impl ConnectedPeers {
    pub fn add_udp_addr(&self, addr: SocketAddr, sender: Sender<EncryptMessage>) {
        self.0.udp_addrs.insert(addr, sender);
    }

    pub fn add_mahiro_ip(&self, addr: IpAddr, sender: Sender<EncryptMessage>) {
        self.0.mahiro_ips.insert(addr, sender);
    }

    pub fn remove_udp_addr(&self, addr: SocketAddr) {
        if let Some((_, sender)) = self.0.udp_addrs.remove(&addr) {
            self.0
                .mahiro_ips
                .retain(|_, other_sender| !sender.same_receiver(other_sender))
        }
    }

    pub fn get_sender_by_udp_addr(&self, addr: SocketAddr) -> Option<Sender<EncryptMessage>> {
        self.0.udp_addrs.get(&addr).map(|sender| sender.clone())
    }

    pub fn get_sender_by_mahiro_ip(&self, addr: IpAddr) -> Option<Sender<EncryptMessage>> {
        self.0.mahiro_ips.get(&addr).map(|sender| sender.clone())
    }
}
