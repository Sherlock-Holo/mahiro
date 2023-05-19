use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub tun_name: String,

    #[serde(deserialize_with = "decode_base64")]
    pub local_private_key: Bytes,

    pub peers: Vec<Peer>,

    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv4: Ipv4Net,
    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv6: Ipv6Net,

    pub listen_addr: SocketAddr,

    #[serde(deserialize_with = "parse_duration")]
    pub heartbeat_interval: Duration,

    pub nic_list: Option<Vec<String>>,

    pub bpf_prog: Option<String>,
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Peer {
    #[serde(deserialize_with = "decode_base64")]
    pub remote_public_key: Bytes,

    pub peer_ipv4: Ipv4Addr,
    pub peer_ipv6: Ipv6Addr,
}

fn decode_base64<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    BASE64_STANDARD
        .decode(string)
        .map_err(Error::custom)
        .map(Bytes::from)
}

fn parse_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    humantime::parse_duration(&string).map_err(Error::custom)
}
