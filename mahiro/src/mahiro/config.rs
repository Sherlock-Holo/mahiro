use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub tun_name: String,

    pub token_secret: String,
    pub public_id: String,

    pub ca_cert: Option<String>,

    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv4: Ipv4Net,
    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv6: Ipv6Net,

    pub remote_url: String,
    pub protocol: Protocol,

    #[serde(deserialize_with = "parse_duration")]
    pub heartbeat_interval: Duration,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http2,
    Websocket,
}

fn parse_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    humantime::parse_duration(&string).map_err(Error::custom)
}
