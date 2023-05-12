use std::collections::HashSet;
use std::path::Path;

use futures_channel::mpsc;
use tokio::fs;

use self::config::Config;
use self::connected_peer::ConnectedPeers;
use self::nat::NatActor;
use self::tun::TunActor;
use self::udp::UdpActor;

mod config;
mod connected_peer;
mod encrypt;
mod message;
mod nat;
mod tun;
mod udp;

pub async fn run(config: &Path, bpf_nat: bool) -> anyhow::Result<()> {
    let config_data = fs::read(config).await?;
    let config = serde_yaml::from_slice::<Config>(&config_data)?;
    let remote_public_keys = config.remote_public_keys();

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let (tun_sender, tun_mailbox) = mpsc::channel(10);
    let (udp_sender, udp_mailbox) = mpsc::channel(10);

    let connected_peers = ConnectedPeers::default();

    let mut tun_actor = TunActor::new(
        tun_sender.clone(),
        tun_mailbox,
        connected_peers.clone(),
        config.local_ipv4,
        config.local_ipv6,
        config.tun_name,
        handle.clone(),
    )
    .await?;

    let mut udp_actor = UdpActor::new(
        udp_sender,
        udp_mailbox,
        connected_peers,
        tun_sender,
        config.listen_addr,
        config.local_private_key,
        config.heartbeat_interval,
        remote_public_keys,
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
