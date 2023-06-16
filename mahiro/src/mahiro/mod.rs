use std::path::Path;

use rustls::{Certificate, ClientConfig, OwnedTrustAnchor, RootCertStore};
use tokio::fs;
use tokio::task::JoinSet;
use tracing::info;
use webpki::TrustAnchor;

use self::config::Config;
use self::tun::{TunActor, TunConfig};
use crate::mahiro::http2::Http2TransportActor;
use crate::token::TokenGenerator;
use crate::util;

mod config;
mod http2;
mod message;
mod tun;

pub async fn run(config: &Path) -> anyhow::Result<()> {
    let config_data = fs::read(config).await?;
    let config = serde_yaml::from_slice::<Config>(&config_data)?;
    let tls_client_config = create_tls_client_config(config.ca_cert.as_deref()).await?;
    let token_generator = TokenGenerator::new(config.token_secret, None)?;

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let tun_config = TunConfig {
        tun_ipv4: config.local_ipv4,
        tun_ipv6: config.local_ipv6,
        tun_name: config.tun_name,
        netlink_handle: handle,
    };

    let (http2_transport_sender, http2_transport_mailbox) = flume::bounded(64);
    let (tun_sender, tun_mailbox) = flume::bounded(64);

    let mut http2transport_actor = Http2TransportActor::new(
        tls_client_config,
        config.remote_url,
        config.public_id,
        token_generator,
        config.heartbeat_interval,
        http2_transport_mailbox.into_stream(),
        tun_sender.clone(),
    )?;
    let mut tun_actor = TunActor::new(
        http2_transport_sender,
        tun_sender,
        tun_mailbox.into_stream(),
        tun_config,
    )
    .await?;

    let mut join_set = JoinSet::new();
    join_set.spawn(async move { http2transport_actor.run().await });
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

async fn create_tls_client_config(ca: Option<&str>) -> anyhow::Result<ClientConfig> {
    let mut store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        store.add(&Certificate(cert.0))?;
    }

    if let Some(ca) = ca {
        let ca_cert = fs::read(ca).await?;
        let ca_certs = rustls_pemfile::certs(&mut ca_cert.as_slice())?;

        let ca_certs = ca_certs
            .iter()
            .map(|cert| {
                let ta = TrustAnchor::try_from_cert_der(cert)?;

                Ok::<_, anyhow::Error>(OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        store.add_server_trust_anchors(ca_certs.into_iter());
    }

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(store)
        .with_no_client_auth();

    Ok(client_config)
}
