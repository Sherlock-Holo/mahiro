use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dashmap::DashMap;
use flume::Sender;

use super::message::TransportMessage;
use crate::util::Receiver;

#[derive(Clone, Debug)]
pub struct PeerStore<T: Send + Sync + Debug + Clone> {
    inner: Arc<PeerStoreInner<T>>,
}

impl<T: Send + Sync + Debug + Clone> PeerStore<T> {
    pub fn new<I: IntoIterator<Item = (String, Ipv4Addr, Ipv6Addr, T)>>(peers_iter: I) -> Self {
        let mut peers = HashMap::new();
        let mut mahiro_ipv4s = HashMap::new();
        let mut mahiro_ipv6s = HashMap::new();

        for (identity, mahiro_ipv4, mahiro_ipv6, info) in peers_iter.into_iter() {
            let (http2_transport_sender, http2_transport_receiver) = flume::bounded(64);
            let peer_channel = Arc::new(PeerChannel {
                http2_transport_sender,
                http2_transport_receiver: http2_transport_receiver.into_stream(),
                info,
            });

            peers.insert(identity, peer_channel.clone());

            mahiro_ipv4s.insert(mahiro_ipv4, peer_channel.clone());
            mahiro_ipv6s.insert(mahiro_ipv6, peer_channel);
        }

        Self {
            inner: Arc::new(PeerStoreInner {
                peers,
                mahiro_ipv4s,
                mahiro_ipv6s,
                mahiro_link_local_ip: Default::default(),
            }),
        }
    }

    pub fn get_transport_receiver_by_identity(
        &self,
        identity: &str,
    ) -> Option<Receiver<TransportMessage>> {
        self.inner
            .peers
            .get(identity)
            .map(|channel| channel.http2_transport_receiver.clone())
    }

    pub fn get_info_by_identity(&self, identity: &str) -> Option<T> {
        self.inner
            .peers
            .get(identity)
            .map(|channel| channel.info.clone())
    }

    pub fn get_transport_sender_by_mahiro_ip(
        &self,
        ip: IpAddr,
    ) -> Option<&Sender<TransportMessage>> {
        match ip {
            IpAddr::V4(ip) => self
                .inner
                .mahiro_ipv4s
                .get(&ip)
                .map(|channel| &channel.http2_transport_sender),
            IpAddr::V6(ip) => self
                .inner
                .mahiro_ipv6s
                .get(&ip)
                .map(|channel| &channel.http2_transport_sender),
        }
    }

    pub fn update_link_local_ip(&self, link_local_ip: Ipv6Addr, identity: &str) {
        if let Some(channel) = self.inner.peers.get(identity) {
            self.inner
                .mahiro_link_local_ip
                .insert(link_local_ip, channel.clone());
        }
    }
}

#[derive(Debug)]
struct PeerStoreInner<T: Send + Sync + Debug + Clone> {
    peers: HashMap<String, Arc<PeerChannel<T>>>,
    mahiro_ipv4s: HashMap<Ipv4Addr, Arc<PeerChannel<T>>>,
    mahiro_ipv6s: HashMap<Ipv6Addr, Arc<PeerChannel<T>>>,
    mahiro_link_local_ip: DashMap<Ipv6Addr, Arc<PeerChannel<T>>>,
}

struct PeerChannel<T: Send + Sync + Debug + Clone> {
    http2_transport_sender: Sender<TransportMessage>,
    http2_transport_receiver: Receiver<TransportMessage>,
    info: T,
}

impl<T: Send + Sync + Debug + Clone> Debug for PeerChannel<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerChannel")
            .field("http2_transport_sender", &"http2_transport_sender")
            .field("http2_transport_receiver", &"http2_transport_receiver")
            .field("info", &self.info)
            .finish()
    }
}

fn _test<T: Send>(_: Option<T>) {}

fn _assert_send<T: Send + Sync + Debug + Clone>() {
    _test::<PeerChannel<T>>(None)
}
