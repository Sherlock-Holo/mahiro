use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub tun_name: String,

    pub peers: Vec<Peer>,

    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv4: Ipv4Net,
    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv6: Ipv6Net,

    pub listen_addr: SocketAddr,
    pub protocol: Protocol,

    pub key: String,
    pub cert: String,

    #[serde(deserialize_with = "parse_duration")]
    pub heartbeat_interval: Duration,

    pub nic_list: Option<Vec<String>>,

    pub bpf_prog: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Deserialize)]
pub enum Protocol {
    Http2,
    Websocket,
}

#[derive(Debug, Deserialize)]
pub struct Peer {
    pub public_id: String,
    pub token_secret: String,

    pub peer_ipv4: Ipv4Addr,
    pub peer_ipv6: Ipv6Addr,
}

fn parse_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    humantime::parse_duration(&string).map_err(Error::custom)
}
