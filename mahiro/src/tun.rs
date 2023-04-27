use std::io;
use std::io::{Error, IoSlice};
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use cidr::{Ipv4Inet, Ipv6Inet};
use derivative::Derivative;
use futures_util::TryStreamExt;
use rtnetlink::Handle;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun::AsyncDevice;

const MTU: u32 = 1400;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Tun {
    ipv4: Ipv4Inet,
    ipv6: Ipv6Inet,
    name: String,
    #[derivative(Debug = "ignore")]
    device: AsyncDevice,
    #[derivative(Debug = "ignore")]
    buf: BytesMut,
}

impl Tun {
    pub async fn new(
        name: String,
        ipv4: Ipv4Inet,
        ipv6: Ipv6Inet,
        netlink_handle: Handle,
    ) -> anyhow::Result<Self> {
        let mut configuration = tun::configure();
        configuration.name(name.clone());

        let device = tun::create_as_async(&configuration)?;

        Tun::setup_device(&name, ipv4, ipv6, netlink_handle).await?;

        Ok(Self {
            ipv4,
            ipv6,
            name,
            device,
            buf: BytesMut::with_capacity(MTU as _),
        })
    }

    async fn setup_device(
        name: &str,
        ipv4: Ipv4Inet,
        ipv6: Ipv6Inet,
        netlink_handle: Handle,
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
            .add(tun_index, IpAddr::V4(ipv4.address()), ipv4.network_length())
            .execute()
            .await?;
        address_handle
            .add(tun_index, IpAddr::V6(ipv6.address()), ipv6.network_length())
            .execute()
            .await?;

        link_handle.set(tun_index).mtu(MTU).up().execute().await?;

        Ok(())
    }
}

impl AsyncWrite for Tun {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.device).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.device).poll_write_vectored(cx, bufs)
    }
}

impl AsyncRead for Tun {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_read(cx, buf)
    }
}
