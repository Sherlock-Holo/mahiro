use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};

use crate::util::parse_duration;

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub tun_name: String,

    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv4: Ipv4Net,
    #[serde_as(as = "DisplayFromStr")]
    pub local_ipv6: Ipv6Net,

    pub protocol: Protocol,

    #[serde(deserialize_with = "parse_duration")]
    pub heartbeat_interval: Duration,
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http2 {
        token_secret: String,
        public_id: String,
        ca_cert: Option<String>,
        remote_url: String,
    },
    Websocket {
        token_secret: String,
        public_id: String,
        ca_cert: Option<String>,
        remote_url: String,
    },
    Quic {
        key: String,
        cert: String,
        ca_cert: Option<String>,
        remote_addr: String,
        r#type: QuicType,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicType {
    Datagram,
    Stream,
}
