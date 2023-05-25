use std::fs::File as StdFile;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::thread;

use derivative::Derivative;
use futures_util::TryStreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use netlink_packet_route::nlas::link::Nla;
use rtnetlink::Handle;
use tap::TapFallible;
use tokio_uring::buf::{IoBuf, IoBufMut};
use tokio_uring::fs::File;
use tokio_uring::BufResult;
use tracing::{error, info};
use tun::platform::Queue;
use tun::Device;

const MTU: u32 = 1280;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Tun {
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
    name: String,
    #[derivative(Debug = "ignore")]
    queues: Vec<Queue>,
}

impl Tun {
    pub async fn new(
        name: String,
        ipv4: Ipv4Net,
        ipv6: Ipv6Net,
        netlink_handle: Handle,
    ) -> anyhow::Result<Self> {
        let queue_size = thread::available_parallelism()
            .unwrap_or(NonZeroUsize::new(8).unwrap())
            .get()
            * 4;
        let mut configuration = tun::configure();
        configuration.name(name.clone()).queues(queue_size);

        let queues = tun::create(&configuration)?.queues();

        Tun::setup_device(&name, ipv4, ipv6, netlink_handle).await?;

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
            // let (reader, writer) = io::split(queue);
            let fd = OwnedFd::from(queue);
            let file = StdFile::from(fd);
            // tokio_uring doesn't have AsyncFd like tokio, but we can convert Queue into
            // tokio_uring File to use io_uring
            let file = Arc::new(File::from_std(file));

            tun_readers.push(TunReader {
                ipv4: self.ipv4,
                ipv6: self.ipv6,
                name: name.clone(),
                queue: file.clone(),
            });
            tun_writers.push(TunWriter {
                ipv4: self.ipv4,
                ipv6: self.ipv6,
                name: name.clone(),
                queue: file,
            });
        });

        (tun_readers, tun_writers)
    }

    async fn setup_device(
        name: &str,
        ipv4: Ipv4Net,
        ipv6: Ipv6Net,
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

        let mut link_set_request = link_handle.set(tun_index).mtu(MTU).up();
        link_set_request
            .message_mut()
            .nlas
            .push(Nla::TxQueueLen(1000));

        link_set_request
            .execute()
            .await
            .tap_err(|err| error!(%err, MTU, "set tun MTU and up failed"))?;

        info!(MTU, "set tun MTU and up done");

        Ok(())
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct TunReader {
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
    name: Arc<str>,
    #[derivative(Debug = "ignore")]
    queue: Arc<File>,
}

impl TunReader {
    #[inline]
    pub async fn read<T: IoBufMut>(&self, buf: T) -> BufResult<usize, T> {
        self.queue.read_at(buf, 0).await
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct TunWriter {
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
    name: Arc<str>,
    #[derivative(Debug = "ignore")]
    queue: Arc<File>,
}

impl TunWriter {
    #[inline]
    pub async fn write<T: IoBuf>(&self, buf: T) -> BufResult<usize, T> {
        self.queue.write_at(buf, 0).await
    }
}
