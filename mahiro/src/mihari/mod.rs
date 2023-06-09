use std::collections::HashSet;
use std::path::Path;

use aya::Bpf;
use tap::TapFallible;
use tokio::fs;
use tokio::task::JoinSet;
use tracing::{error, info};

use self::config::Config;
use self::nat::NatActor;
use self::peer_store::PeerStore;
use self::tun::TunActor;
use self::udp::UdpActor;
use crate::public_key::PublicKey;
use crate::util;

mod config;
mod encrypt;
mod message;
mod nat;
mod peer_store;
mod tun;
mod udp;

pub async fn run(config: &Path, bpf_nat: bool, bpf_forward: bool) -> anyhow::Result<()> {
    let config_data = fs::read(config).await?;
    let config = serde_yaml::from_slice::<Config>(&config_data)?;

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let (tun_sender, tun_mailbox) = flume::bounded(64);
    let (udp_sender, udp_mailbox) = flume::bounded(64);

    let peer_store = PeerStore::from(config.peers.into_iter().map(|peer| {
        (
            PublicKey::from(peer.remote_public_key),
            (peer.peer_ipv4, peer.peer_ipv6),
        )
    }));

    let mut tun_actor = TunActor::new(
        tun_sender.clone(),
        tun_mailbox.into_stream(),
        peer_store.clone(),
        config.local_ipv4,
        config.local_ipv6,
        config.tun_name.clone(),
        handle.clone(),
    )
    .await?;

    let mut udp_actor = UdpActor::new(
        udp_sender,
        udp_mailbox.into_stream(),
        peer_store,
        tun_sender,
        config.listen_addr,
        config.local_private_key,
        config.heartbeat_interval,
    )
    .await?;

    let mut join_set = JoinSet::new();
    join_set.spawn(async move {
        tun_actor.run().await;

        Ok(())
    });
    join_set.spawn(async move {
        udp_actor.run().await;

        Ok(())
    });

    if bpf_nat || bpf_forward {
        info!(bpf_nat, bpf_forward, "enable bpf nat mode");

        let bpf_prog = config
            .bpf_prog
            .ok_or_else(|| anyhow::anyhow!("bpf prog not set"))?;

        let bpf = Bpf::load_file(&bpf_prog).tap_err(|err| {
            error!(%err, ?bpf_prog, "load bpf failed");
        })?;

        if bpf_nat {
            let mut nat_actor = NatActor::new(
                handle,
                config.local_ipv4,
                config.local_ipv6,
                HashSet::from_iter(config.nic_list.unwrap_or_default()),
                bpf_forward,
                &config.tun_name,
                bpf,
            )?;

            join_set.spawn(async move { nat_actor.run().await });
        }
    }

    tokio::select! {
        _ = join_set.join_next() => {
            Err(anyhow::anyhow!("actors stopped"))
        }

        result = util::stop_signal() => {
            result?;

            info!("mihari stopping");

            join_set.shutdown().await;

            Ok(())
        }
    }
}
