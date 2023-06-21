use std::cmp::Ordering;
use std::io;
use std::io::{Error, ErrorKind, IoSlice};
use std::net::SocketAddr;
use std::net::TcpStream as StdTcpStream;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::raw::c_int;
use std::pin::Pin;
use std::task::{Context, Poll};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net;
use tokio::net::{TcpStream, ToSocketAddrs};

#[derive(Debug)]
pub struct MptcpStream {
    inner: TcpStream,
}

impl MptcpStream {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let mut addrs = net::lookup_host(addr).await?.collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(Error::new(ErrorKind::Other, "lookup host returns no addr"));
        }

        // make sure ipv6 first
        addrs.sort_by(|addr1, addr2| {
            if addr1.is_ipv6() && addr2.is_ipv4() {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        });

        let socket = Self::create_socket(addrs)?;
        let std_tcp_stream = unsafe { StdTcpStream::from_raw_fd(socket.into_raw_fd()) };
        let tcp_stream = TcpStream::from_std(std_tcp_stream)?;
        tcp_stream.ready(Interest::WRITABLE).await?;

        Ok(Self { inner: tcp_stream })
    }

    fn create_socket(addrs: Vec<SocketAddr>) -> io::Result<Socket> {
        let mut last_err = None;
        for addr in addrs {
            let domain = Domain::for_address(addr);
            let addr = SockAddr::from(addr);
            let mut sock_type: c_int = Type::STREAM.into();
            sock_type |= libc::SOCK_NONBLOCK;

            let socket = match Socket::new(domain, sock_type.into(), Some(Protocol::MPTCP)) {
                Err(err) => {
                    last_err = Some(err);

                    continue;
                }

                Ok(socket) => socket,
            };

            if let Err(err) = socket.set_nonblocking(true) {
                last_err = Some(err);

                continue;
            }

            if let Err(err) = socket.connect(&addr) {
                if err.kind() != ErrorKind::WouldBlock
                    && err.raw_os_error() != Some(libc::EINPROGRESS)
                {
                    last_err = Some(err);

                    continue;
                }
            }

            return Ok(socket);
        }

        Err(last_err.unwrap())
    }

    #[inline]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    pub(crate) fn new(tcp_stream: TcpStream) -> Self {
        Self { inner: tcp_stream }
    }
}

impl AsyncRead for MptcpStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = Pin::new(&mut self.inner);

        inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for MptcpStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let inner = Pin::new(&mut self.inner);

        inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let inner = Pin::new(&mut self.inner);

        inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let inner = Pin::new(&mut self.inner);

        inner.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        let inner = Pin::new(&mut self.inner);

        inner.poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
