use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use cidr::{IpInet, Ipv4Inet, Ipv6Inet};
use futures_util::TryStreamExt;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use serde_with::{serde_as, DisplayFromStr};
use tap::TapFallible;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::wrappers::LinesStream;
use tracing::error;

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub tun_name: String,

    #[serde(deserialize_with = "decode_base64")]
    pub local_private_key: Bytes,
    #[serde(deserialize_with = "decode_base64")]
    pub remote_public_key: Bytes,

    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv4: Ipv4Inet,
    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv6: Ipv6Inet,

    pub remote_addr: SocketAddr,

    #[serde(deserialize_with = "parse_duration")]
    pub heartbeat_interval: Duration,

    #[serde(default)]
    pub ip_list: Vec<PathBuf>,
}

pub async fn collect_ips(ip_list: &[PathBuf]) -> anyhow::Result<(Vec<Ipv4Inet>, Vec<Ipv6Inet>)> {
    let mut ipv4s = vec![];
    let mut ipv6s = vec![];

    for path in ip_list {
        let file = File::open(path)
            .await
            .tap_err(|err| error!(%err, ?path, "open ip file failed"))?;
        let mut lines = LinesStream::new(BufReader::new(file).lines());

        while let Some(line) = lines
            .try_next()
            .await
            .tap_err(|err| error!(%err, "get ip failed"))?
        {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match IpInet::from_str(line).tap_err(|err| error!(%err, line, "parse ip failed"))? {
                IpInet::V4(ipv4) => ipv4s.push(ipv4),
                IpInet::V6(ipv6) => ipv6s.push(ipv6),
            }
        }
    }

    Ok((ipv4s, ipv6s))
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
