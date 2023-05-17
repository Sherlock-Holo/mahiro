use std::path::Path;

use tokio::fs;

use self::config::Config;
use self::encrypt::EncryptActor;
use self::tun::{TunActor, TunConfig};
use self::udp::UdpActor;

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

    let udp_actor_task = tokio::spawn(async move { udp_actor.run().await });
    let encrypt_actor_task = tokio::spawn(async move { encrypt_actor.run().await });
    let tun_actor_task = tokio::spawn(async move { tun_actor.run().await });

    for task in [udp_actor_task, encrypt_actor_task, tun_actor_task] {
        task.await.unwrap();
    }

    Err(anyhow::anyhow!("actors stopped"))
}
