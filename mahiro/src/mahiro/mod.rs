use std::path::Path;

use tokio::fs;
use tokio::task::JoinSet;
use tracing::info;

use self::config::Config;
use self::encrypt::EncryptActor;
use self::tun::{TunActor, TunConfig};
use self::udp::UdpActor;
use crate::util;

mod config;
mod encrypt;
mod message;
mod tun;
mod udp;

pub async fn run(config: &Path) -> anyhow::Result<()> {
    let config_data = fs::read(config).await?;
    let config = serde_yaml::from_slice::<Config>(&config_data)?;

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let tun_config = TunConfig {
        tun_ipv4: config.local_ipv4,
        tun_ipv6: config.local_ipv6,
        tun_name: config.tun_name,
        netlink_handle: handle,
    };

    let (encrypt_sender, encrypt_mailbox) = flume::bounded(64);
    let (udp_sender, udp_mailbox) = flume::bounded(64);
    let (tun_sender, tun_mailbox) = flume::bounded(64);

    let mut udp_actor = UdpActor::new(
        encrypt_sender.clone(),
        udp_sender.clone(),
        udp_mailbox.into_stream(),
        config.peer_addr,
    )
    .await?;
    let mut encrypt_actor = EncryptActor::new(
        udp_sender,
        tun_sender.clone(),
        encrypt_sender.clone(),
        encrypt_mailbox.into_stream(),
        config.heartbeat_interval,
        config.local_private_key,
        config.peer_public_key.into(),
    )
    .await?;
    let mut tun_actor = TunActor::new(
        encrypt_sender,
        tun_sender,
        tun_mailbox.into_stream(),
        tun_config,
    )
    .await?;

    let mut join_set = JoinSet::new();
    join_set.spawn(async move { udp_actor.run().await });
    join_set.spawn(async move { encrypt_actor.run().await });
    join_set.spawn(async move { tun_actor.run().await });

    tokio::select! {
        _ = join_set.join_next() => {
            Err(anyhow::anyhow!("actors stopped"))
        }

        result = util::stop_signal() => {
            result?;

            info!("mahiro stopping");

            join_set.shutdown().await;

            Ok(())
        }
    }
}
