use std::time::Duration;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use cidr::{Ipv4Inet, Ipv6Inet};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub tun_name: String,

    #[serde(deserialize_with = "decode_base64")]
    pub local_private_key: Bytes,
    #[serde(deserialize_with = "decode_base64")]
    pub peer_public_key: Bytes,

    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv4: Ipv4Inet,
    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv6: Ipv6Inet,

    pub peer_addr: String,

    #[serde(deserialize_with = "parse_duration")]
    pub heartbeat_interval: Duration,
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
