use std::collections::HashSet;
use std::path::Path;

use futures_channel::mpsc;
use tokio::fs;

use self::config::Config;
use self::nat::NatActor;
use self::peer_store::PeerStore;
use self::tun::TunActor;
use self::udp::UdpActor;
use crate::public_key::PublicKey;

mod config;
mod encrypt;
mod message;
mod nat;
mod peer_store;
mod tun;
mod udp;

pub async fn run(config: &Path, bpf_nat: bool) -> anyhow::Result<()> {
    let config_data = fs::read(config).await?;
    let config = serde_yaml::from_slice::<Config>(&config_data)?;

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let (tun_sender, tun_mailbox) = mpsc::channel(10);
    let (udp_sender, udp_mailbox) = mpsc::channel(10);

    let peer_store = PeerStore::from(config.peers.into_iter().map(|peer| {
        (
            PublicKey::from(peer.remote_public_key),
            (peer.peer_ipv4, peer.peer_ipv6),
        )
    }));

    let mut tun_actor = TunActor::new(
        tun_sender.clone(),
        tun_mailbox,
        peer_store.clone(),
        config.local_ipv4,
        config.local_ipv6,
        config.tun_name,
        handle.clone(),
    )
    .await?;

    let mut udp_actor = UdpActor::new(
        udp_sender,
        udp_mailbox,
        peer_store,
        tun_sender,
        config.listen_addr,
        config.local_private_key,
        config.heartbeat_interval,
    )
    .await?;

    let tun_actor_task = tokio::spawn(async move { tun_actor.run().await });
    let udp_actor_task = tokio::spawn(async move { udp_actor.run().await });

    if bpf_nat {
        let bpf_prog = config
            .bpf_prog
            .ok_or_else(|| anyhow::anyhow!("bpf prog not set"))?;

        let mut nat_actor = NatActor::new(
            handle,
            config.local_ipv4,
            config.local_ipv6,
            HashSet::from_iter(config.nic_list.unwrap_or_default()),
            Path::new(&bpf_prog),
        )?;

        let nat_actor_task = tokio::spawn(async move { nat_actor.run().await });

        tokio::select! {
            _ = nat_actor_task => {}
            _ = tun_actor_task => {}
            _ = udp_actor_task => {}
        }
    } else {
        tokio::select! {
            _ = tun_actor_task => {}
            _ = udp_actor_task => {}
        }
    }

    Err(anyhow::anyhow!("mihari stopped unexpected"))
}
