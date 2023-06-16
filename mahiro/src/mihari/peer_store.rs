use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dashmap::DashMap;
use flume::Sender;

use super::message::Http2Message;
use crate::util::Receiver;

#[derive(Clone, Debug)]
pub struct PeerStore {
    inner: Arc<PeerStoreInner>,
}

impl PeerStore {
    pub fn new<I: IntoIterator<Item = (String, Ipv4Addr, Ipv6Addr)>>(peers_iter: I) -> Self {
        let mut peers = HashMap::new();
        let mut mahiro_ipv4s = HashMap::new();
        let mut mahiro_ipv6s = HashMap::new();

        for (public_id, mahiro_ipv4, mahiro_ipv6) in peers_iter.into_iter() {
            let (http2_transport_sender, http2_transport_receiver) = flume::bounded(64);
            let peer_channel = Arc::new(PeerChannel {
                http2_transport_sender,
                http2_transport_receiver: http2_transport_receiver.into_stream(),
            });

            peers.insert(public_id, peer_channel.clone());

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

    pub fn get_http2_transport_receiver_by_public_id(
        &self,
        public_id: &str,
    ) -> Option<Receiver<Http2Message>> {
        self.inner
            .peers
            .get(public_id)
            .map(|channel| channel.http2_transport_receiver.clone())
    }

    pub fn get_http2_transport_sender_by_mahiro_ip(
        &self,
        ip: IpAddr,
    ) -> Option<&Sender<Http2Message>> {
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

    pub fn update_link_local_ip(&self, link_local_ip: Ipv6Addr, public_id: &str) {
        if let Some(channel) = self.inner.peers.get(public_id) {
            self.inner
                .mahiro_link_local_ip
                .insert(link_local_ip, channel.clone());
        }
    }
}

#[derive(Debug)]
struct PeerStoreInner {
    peers: HashMap<String, Arc<PeerChannel>>,
    mahiro_ipv4s: HashMap<Ipv4Addr, Arc<PeerChannel>>,
    mahiro_ipv6s: HashMap<Ipv6Addr, Arc<PeerChannel>>,
    mahiro_link_local_ip: DashMap<Ipv6Addr, Arc<PeerChannel>>,
}

struct PeerChannel {
    http2_transport_sender: Sender<Http2Message>,
    http2_transport_receiver: Receiver<Http2Message>,
}

impl Debug for PeerChannel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerChannel")
            .field("http2_transport_sender", &"http2_transport_sender")
            .field("http2_transport_receiver", &"http2_transport_receiver")
            .finish()
    }
}
