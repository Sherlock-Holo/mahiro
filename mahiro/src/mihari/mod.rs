use std::collections::HashSet;
use std::path::Path;

use aya::Bpf;
use futures_util::FutureExt;
use tap::TapFallible;
use tokio::fs;
use tokio::task::JoinSet;
use tracing::{error, info};

use self::config::PeerAuth;
use self::config::{Config, Protocol};
use self::http2::Http2TransportActor;
use self::nat::NatActor;
use self::peer_store::PeerStore;
use self::quic::{CommonNameAuthStore, QuicTlsConfig, QuicTransportActor, QuicType};
use self::tun::TunActor;
use self::websocket::WebsocketTransportActor;
use crate::token::AuthStore;
use crate::util;

mod config;
mod http2;
mod message;
mod nat;
mod peer_store;
mod quic;
mod tun;
mod websocket;

pub async fn run(config: &Path, bpf_nat: bool, bpf_forward: bool) -> anyhow::Result<()> {
    let config_data = fs::read(config).await?;
    let config = serde_yaml::from_slice::<Config>(&config_data)?;

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let (tun_sender, tun_mailbox) = flume::bounded(64);

    let peer_store = PeerStore::new(config.peers.iter().map(|peer| match &peer.auth {
        PeerAuth::Http { public_id, .. } | PeerAuth::Websocket { public_id, .. } => (
            public_id.clone(),
            peer.peer_ipv4,
            peer.peer_ipv6,
            QuicType::Stream,
        ),
        PeerAuth::Quic {
            common_name,
            quic_type,
        } => {
            let quic_type = match quic_type {
                config::QuicType::Datagram => QuicType::Datagram,
                config::QuicType::Stream => QuicType::Stream,
            };

            (
                common_name.clone(),
                peer.peer_ipv4,
                peer.peer_ipv6,
                quic_type,
            )
        }
    }));

    let auth_store = AuthStore::new(config.peers.iter().filter_map(|peer| match &peer.auth {
        PeerAuth::Http {
            public_id,
            token_secret,
        }
        | PeerAuth::Websocket {
            public_id,
            token_secret,
        } => Some((public_id.clone(), token_secret.clone())),
        PeerAuth::Quic { .. } => None,
    }))?;

    let common_name_auth_store =
        CommonNameAuthStore::new(config.peers.into_iter().filter_map(|peer| match peer.auth {
            PeerAuth::Http { .. } | PeerAuth::Websocket { .. } => None,
            PeerAuth::Quic { common_name, .. } => Some(common_name),
        }));

    let mut tun_actor = TunActor::new(
        tun_sender.clone(),
        tun_mailbox.into_stream(),
        peer_store.clone(),
        config.local_ipv4,
        config.local_ipv6,
        config.tun_name.clone(),
        handle.clone(),
    )
    .await?;

    let transport_actor_fut = match config.protocol {
        Protocol::Http2 => {
            let mut http2_transport_actor = Http2TransportActor::new(
                tun_sender,
                auth_store,
                peer_store,
                config.listen_addr,
                &config.cert,
                &config.key,
                config.heartbeat_interval,
            )
            .await?;

            async move { http2_transport_actor.run().await }.boxed()
        }

        Protocol::Websocket => {
            let mut websocket_transport_actor = WebsocketTransportActor::new(
                tun_sender,
                auth_store,
                peer_store,
                config.listen_addr,
                &config.cert,
                &config.key,
                config.heartbeat_interval,
            )
            .await?;

            async move { websocket_transport_actor.run().await }.boxed()
        }

        Protocol::Quic => {
            let ca_cert = config
                .ca_cert
                .ok_or_else(|| anyhow::anyhow!("quic mode need ca_cert"))?;

            let mut quic_transport_actor = QuicTransportActor::new(
                tun_sender,
                common_name_auth_store,
                peer_store,
                config.listen_addr,
                QuicTlsConfig {
                    ca: &ca_cert,
                    key: &config.key,
                    cert: &config.cert,
                },
                config.heartbeat_interval,
            )
            .await?;

            async move { quic_transport_actor.run().await }.boxed()
        }
    };

    let mut join_set = JoinSet::new();
    join_set.spawn(async move {
        tun_actor.run().await;

        Ok(())
    });
    join_set.spawn(transport_actor_fut);

    if bpf_nat || bpf_forward {
        info!(bpf_nat, bpf_forward, "enable bpf nat mode");

        let bpf_prog = config
            .bpf_prog
            .ok_or_else(|| anyhow::anyhow!("bpf prog not set"))?;

        let bpf = Bpf::load_file(&bpf_prog).tap_err(|err| {
            error!(%err, ?bpf_prog, "load bpf failed");
        })?;

        if bpf_nat {
            let mut nat_actor = NatActor::new(
                handle,
                config.local_ipv4,
                config.local_ipv6,
                HashSet::from_iter(config.nic_list.unwrap_or_default()),
                bpf_forward,
                &config.tun_name,
                bpf,
            )?;

            join_set.spawn(async move { nat_actor.run().await });
        }
    }

    tokio::select! {
        _ = join_set.join_next() => {
            Err(anyhow::anyhow!("actors stopped"))
        }

        result = util::stop_signal() => {
            result?;

            info!("mihari stopping");

            join_set.shutdown().await;

            Ok(())
        }
    }
}
