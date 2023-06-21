pub use self::listener::MptcpListener;
pub use self::stream::MptcpStream;

mod listener;
mod stream;

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn test() {
        let listener = MptcpListener::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)).unwrap();
        let addr = listener.local_addr().unwrap();

        let task = tokio::spawn(async move { MptcpStream::connect(addr).await.unwrap() });

        let (mut stream1, _) = listener.accept().await.unwrap();
        let mut stream2 = task.await.unwrap();

        assert_eq!(stream2.peer_addr().unwrap(), addr);

        stream1.write_all(b"test").await.unwrap();

        let mut buf = [0; 4];
        stream2.read_exact(&mut buf).await.unwrap();

        assert_eq!(buf.as_slice(), b"test");
    }
}
