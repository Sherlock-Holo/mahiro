use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cidr::IpInet;
use futures_util::{stream, Stream, TryStreamExt};
use tap::TapFallible;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::wrappers::LinesStream;
use tracing::{error, instrument};

use self::route_table::{RouteEntry, RouteEntryAction, RouteTable};

mod route_table;

#[instrument(err)]
pub async fn clean_route() -> anyhow::Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    RouteTable::new(handle).clean().await
}

#[instrument(skip(paths), err)]
pub async fn set_route(
    paths: impl IntoIterator<Item = &str>,
    default_nic: String,
) -> anyhow::Result<()> {
    let mut route_entries = stream::iter(paths.into_iter().map(Ok))
        .and_then(|path| async move { parse_ip_net(path).await })
        .try_flatten()
        .map_ok(|ip_inet| RouteEntry {
            prefix: ip_inet.network_length(),
            addr: ip_inet.address(),
            action: RouteEntryAction::Throw,
        })
        .try_collect::<Vec<_>>()
        .await?;

    route_entries.extend([
        RouteEntry {
            prefix: 0,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            action: RouteEntryAction::OutIface(default_nic.clone()),
        },
        RouteEntry {
            prefix: 0,
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            action: RouteEntryAction::OutIface(default_nic),
        },
    ]);

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let mut route_table = RouteTable::new(handle);

    route_table.clean().await?;
    route_table.set_route(&route_entries).await
}

#[instrument(err)]
async fn parse_ip_net(path: &str) -> anyhow::Result<impl Stream<Item = anyhow::Result<IpInet>>> {
    let file = File::open(path)
        .await
        .tap_err(|err| error!(%err, path, "open file failed"))?;
    let lines = LinesStream::new(BufReader::new(file).lines());

    Ok(lines
        .map_err(anyhow::Error::from)
        .try_filter_map(|line| async move {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                return Ok(None);
            }

            let ip_inet: IpInet = line
                .parse()
                .tap_err(|err| error!(%err, line, "parse line failed"))?;

            Ok(Some(ip_inet))
        }))
}
