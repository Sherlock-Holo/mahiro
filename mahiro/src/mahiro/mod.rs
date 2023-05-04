use std::net::IpAddr;
use std::path::Path;

use cidr::{Ipv4Inet, Ipv6Inet};
use futures_channel::mpsc;
use tokio::fs;

use crate::route_table::RouteEntry;

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

    let (ipv4s, ipv6s) = config::collect_ips(&config.ip_list).await?;

    let route_entries = convert_route_entries(&config.tun_name, ipv4s, ipv6s);

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let tun_config = TunConfig {
        tun_ipv4: config.local_ipv4,
        tun_ipv6: config.local_ipv6,
        tun_name: config.tun_name,
        netlink_handle: handle,
        route_entries,
    };

    let (encrypt_sender, encrypt_mailbox) = mpsc::channel(10);
    let (udp_sender, udp_mailbox) = mpsc::channel(10);
    let (tun_sender, tun_mailbox) = mpsc::channel(10);

    let mut udp_actor = UdpActor::new(
        encrypt_sender.clone(),
        udp_sender.clone(),
        udp_mailbox,
        config.remote_addr,
    )
    .await?;
    let mut encrypt_actor = EncryptActor::new(
        udp_sender,
        tun_sender.clone(),
        encrypt_sender.clone(),
        encrypt_mailbox,
        config.heartbeat_interval,
        config.local_private_key,
        config.remote_public_key,
    )
    .await?;
    let mut tun_actor = TunActor::new(encrypt_sender, tun_sender, tun_mailbox, tun_config).await?;

    let udp_actor_task = tokio::spawn(async move { udp_actor.run().await });
    let encrypt_actor_task = tokio::spawn(async move { encrypt_actor.run().await });
    let tun_actor_task = tokio::spawn(async move { tun_actor.run().await });

    for task in [udp_actor_task, encrypt_actor_task, tun_actor_task] {
        task.await.unwrap();
    }

    Err(anyhow::anyhow!("actors stopped"))
}

fn convert_route_entries(
    tun_name: &str,
    ipv4s: Vec<Ipv4Inet>,
    ipv6s: Vec<Ipv6Inet>,
) -> Vec<RouteEntry> {
    let ipv4s = ipv4s.into_iter().map(|ipv4| RouteEntry {
        prefix: ipv4.network_length(),
        addr: IpAddr::V4(ipv4.first_address()),
        out_iface: tun_name.to_string(),
    });
    let ipv6s = ipv6s.into_iter().map(|ipv6| RouteEntry {
        prefix: ipv6.network_length(),
        addr: IpAddr::V6(ipv6.first_address()),
        out_iface: tun_name.to_string(),
    });

    ipv4s.chain(ipv6s).collect()
}
