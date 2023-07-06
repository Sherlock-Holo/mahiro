use std::path::Path;

use tokio::fs;
use tokio::task::JoinSet;
use tracing::info;

use self::config::{Config, Protocol};
use self::tun::{TunActor, TunConfig};
use crate::mahiro::config::QuicType as ConfigQuicType;
use crate::mahiro::http2::Http2TransportActor;
use crate::mahiro::quic::{QuicTlsConfig, QuicTransportActor, QuicType};
use crate::mahiro::websocket::WebsocketTransportActor;
use crate::token::TokenGenerator;
use crate::util;

mod config;
mod http2;
mod message;
mod quic;
mod tun;
mod websocket;

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
        mtu: config.mtu,
    };

    let (http2_transport_sender, transport_mailbox) = flume::bounded(64);
    let (tun_sender, tun_mailbox) = flume::bounded(64);

    let mut tun_actor = TunActor::new(
        http2_transport_sender,
        tun_sender.clone(),
        tun_mailbox.into_stream(),
        tun_config,
    )
    .await?;

    let mut join_set = JoinSet::new();

    match config.protocol {
        Protocol::Http2 {
            token_secret,
            public_id,
            ca_cert,
            remote_url,
        } => {
            let token_generator = TokenGenerator::new(token_secret, None)?;

            let mut http2_transport_actor = Http2TransportActor::new(
                ca_cert.as_deref(),
                remote_url,
                public_id,
                token_generator,
                config.heartbeat_interval,
                transport_mailbox.into_stream(),
                tun_sender,
            )
            .await?;

            join_set.spawn(async move { http2_transport_actor.run().await });
        }

        Protocol::Websocket {
            token_secret,
            public_id,
            ca_cert,
            remote_url,
        } => {
            let token_generator = TokenGenerator::new(token_secret, None)?;

            let mut websocket_transport_actor = WebsocketTransportActor::new(
                ca_cert.as_deref(),
                remote_url,
                public_id,
                token_generator,
                config.heartbeat_interval,
                transport_mailbox.into_stream(),
                tun_sender,
            )
            .await?;

            join_set.spawn(async move { websocket_transport_actor.run().await });
        }

        Protocol::Quic {
            key,
            cert,
            ca_cert,
            remote_addr,
            r#type,
            rebind_interval,
        } => {
            let quic_type = match r#type {
                ConfigQuicType::Datagram => QuicType::Datagram,
                ConfigQuicType::Stream => QuicType::Stream,
            };

            let mut quic_transport_actor = QuicTransportActor::new(
                QuicTlsConfig {
                    ca: ca_cert.as_deref(),
                    key: &key,
                    cert: &cert,
                },
                &remote_addr,
                config.heartbeat_interval,
                transport_mailbox.into_stream(),
                tun_sender,
                rebind_interval,
                quic_type,
            )
            .await?;

            join_set.spawn(async move { quic_transport_actor.run().await });
        }
    }

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
