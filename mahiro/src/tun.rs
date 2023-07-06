use std::io::{Error, IoSlice};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;

use derivative::Derivative;
use futures_util::TryStreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use netlink_packet_route::nlas::link::Nla;
use rtnetlink::Handle;
use tap::TapFallible;
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tracing::{error, info};
use tun::AsyncQueue;

const DEFAULT_MTU: u32 = 1280;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Tun {
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
    name: String,
    #[derivative(Debug = "ignore")]
    queues: Vec<AsyncQueue>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct TunReader {
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
    name: Arc<str>,
    #[derivative(Debug = "ignore")]
    queue: ReadHalf<AsyncQueue>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct TunWriter {
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
    name: Arc<str>,
    #[derivative(Debug = "ignore")]
    queue: WriteHalf<AsyncQueue>,
}

impl Tun {
    pub async fn new(
        name: String,
        ipv4: Ipv4Net,
        ipv6: Ipv6Net,
        netlink_handle: Handle,
        mtu: Option<u16>,
    ) -> anyhow::Result<Self> {
        let queue_size = thread::available_parallelism()
            .unwrap_or(NonZeroUsize::new(8).unwrap())
            .get()
            * 4;
        let mut configuration = tun::configure();
        configuration.name(name.clone()).queues(queue_size);

        let queues = tun::create_queue_as_async(&configuration)?;

        Tun::setup_device(&name, ipv4, ipv6, netlink_handle, mtu).await?;

        Ok(Self {
            ipv4,
            ipv6,
            name,
            queues,
        })
    }

    pub fn split_queues(self) -> (Vec<TunReader>, Vec<TunWriter>) {
        let name: Arc<str> = self.name.into();

        let mut tun_readers = Vec::with_capacity(self.queues.len());
        let mut tun_writers = Vec::with_capacity(self.queues.len());
        self.queues.into_iter().for_each(|queue| {
            let (reader, writer) = io::split(queue);

            tun_readers.push(TunReader {
                ipv4: self.ipv4,
                ipv6: self.ipv6,
                name: name.clone(),
                queue: reader,
            });
            tun_writers.push(TunWriter {
                ipv4: self.ipv4,
                ipv6: self.ipv6,
                name: name.clone(),
                queue: writer,
            });
        });

        (tun_readers, tun_writers)
    }

    async fn setup_device(
        name: &str,
        ipv4: Ipv4Net,
        ipv6: Ipv6Net,
        netlink_handle: Handle,
        mtu: Option<u16>,
    ) -> anyhow::Result<()> {
        let mut link_handle = netlink_handle.link();
        let tun_index = match link_handle
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await?
        {
            None => {
                return Err(anyhow::anyhow!("created {name} tun miss"));
            }

            Some(link) => link.header.index,
        };

        let address_handle = netlink_handle.address();
        address_handle
            .add(tun_index, IpAddr::V4(ipv4.addr()), ipv4.prefix_len())
            .execute()
            .await
            .tap_err(|err| error!(%err, "add ipv4 addr failed"))?;
        address_handle
            .add(tun_index, IpAddr::V6(ipv6.addr()), ipv6.prefix_len())
            .execute()
            .await
            .tap_err(|err| error!(%err, "addr ipv6 addr failed"))?;

        info!("add ipv4 and ipv6 addr done");

        let mtu = mtu.map(|mtu| mtu as u32).unwrap_or(DEFAULT_MTU);

        let mut link_set_request = link_handle.set(tun_index).mtu(mtu).up();
        link_set_request
            .message_mut()
            .nlas
            .push(Nla::TxQueueLen(1000));

        link_set_request
            .execute()
            .await
            .tap_err(|err| error!(%err, mtu, "set tun MTU and up failed"))?;

        info!(mtu, "set tun MTU and up done");

        Ok(())
    }
}

impl AsyncWrite for TunWriter {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.queue).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.queue).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.queue).poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.queue).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.queue.is_write_vectored()
    }
}

impl AsyncRead for TunReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.queue).poll_read(cx, buf)
    }
}
