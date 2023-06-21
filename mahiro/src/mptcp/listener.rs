use std::io;
use std::net::SocketAddr;
use std::net::TcpListener as StdTcpListener;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use futures_util::Stream;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpListener;

use crate::mptcp::MptcpStream;

#[derive(Debug)]
pub struct MptcpListener {
    inner: TcpListener,
}

impl MptcpListener {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let domain = Domain::for_address(addr);
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::MPTCP))?;
        let addr = SockAddr::from(addr);

        socket.bind(&addr)?;
        socket.listen(1024)?;
        let std_tcp_listener = unsafe { StdTcpListener::from_raw_fd(socket.into_raw_fd()) };

        let tcp_listener = TcpListener::from_std(std_tcp_listener)?;

        Ok(MptcpListener {
            inner: tcp_listener,
        })
    }

    #[inline]
    pub async fn accept(&self) -> io::Result<(MptcpStream, SocketAddr)> {
        let (tcp_stream, addr) = self.inner.accept().await?;
        let mptcp_stream = MptcpStream::new(tcp_stream);

        Ok((mptcp_stream, addr))
    }

    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl Stream for &MptcpListener {
    type Item = io::Result<MptcpStream>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (tcp_stream, _) = ready!(self.inner.poll_accept(cx))?;

        Poll::Ready(Some(Ok(MptcpStream::new(tcp_stream))))
    }
}
