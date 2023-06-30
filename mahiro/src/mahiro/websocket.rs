use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use http::{HeaderValue, StatusCode, Uri};
use rustls::ClientConfig;
use tap::TapFallible;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time as tokio_time;
use tokio_stream::wrappers::IntervalStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{tungstenite, Connector, MaybeTlsStream, WebSocketStream};
use tracing::{error, info, instrument, warn};

use super::message::TransportMessage as Message;
use super::message::TunMessage;
use crate::token::TokenGenerator;
use crate::util;
use crate::util::{Receiver, HMAC_HEADER, PUBLIC_ID_HEADER, WEBSOCKET_TRANSPORT_COUNT};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct WebsocketTransportActor {
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    tun_sender: Sender<TunMessage>,

    client_config: Arc<ClientConfig>,
    remote_url: Uri,
    public_id: String,
    token_generator: TokenGenerator,
    heartbeat_interval: Duration,
    transport_count: u8,
}

impl WebsocketTransportActor {
    pub async fn new(
        ca: Option<&str>,
        remote_url: String,
        public_id: String,
        token_generator: TokenGenerator,
        heartbeat_interval: Duration,
        mailbox: Receiver<Message>,
        tun_sender: Sender<TunMessage>,
    ) -> anyhow::Result<Self> {
        let remote_url: Uri = remote_url
            .parse()
            .tap_err(|err| error!(%err, %remote_url, "parse remote url failed"))?;

        let client_config = util::create_tls_client_config(None, ca).await?;

        Ok(Self {
            mailbox,
            tun_sender,
            client_config: Arc::new(client_config),
            remote_url,
            public_id,
            token_generator,
            heartbeat_interval,
            transport_count: WEBSOCKET_TRANSPORT_COUNT,
        })
    }

    pub async fn run(&mut self) {
        loop {
            if let Err(err) = self.run_circle().await {
                error!(%err, "websocket actor run circle failed");
            }
        }
    }

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();

        for _ in 0..self.transport_count {
            let websocket = self
                .open_transport()
                .await
                .tap_err(|err| error!(%err, "open transport failed"))?;
            let mailbox = self.mailbox.clone();
            let tun_sender = self.tun_sender.clone();
            let heartbeat_interval = self.heartbeat_interval;

            join_set.spawn(async move {
                Self::run_transport(websocket, tun_sender, mailbox, heartbeat_interval).await
            });
        }

        join_set.join_next().await.unwrap().unwrap();

        Err(anyhow::anyhow!("websocket actor stopped"))
    }

    #[instrument(err)]
    async fn open_transport(&self) -> anyhow::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let hmac = self.token_generator.generate_token();

        let mut request = self.remote_url.clone().into_client_request().tap_err(|err| {
            error!(%err, remote_url = %self.remote_url, "convert remote url to http request failed")
        })?;

        {
            let public_id = HeaderValue::from_str(&self.public_id)
                .tap_err(|err| error!(%err, "public id invalid"))?;
            let hmac = HeaderValue::from_str(&hmac).tap_err(|err| error!(%err, "hmac invalid"))?;

            let headers = request.headers_mut();
            headers.insert(PUBLIC_ID_HEADER, public_id);
            headers.insert(HMAC_HEADER, hmac);
        }

        let (websocket, response) = tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            true,
            Some(Connector::Rustls(self.client_config.clone())),
        )
        .await
        .tap_err(|err| error!(%err, "open websocket failed"))?;

        info!(%hmac, "receive websocket response done");

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let status_code = response.status();
            error!(%status_code, %hmac, "status code is not 101");

            return Err(anyhow::anyhow!("status code is not 101"));
        }

        info!(%hmac, "get websocket done");

        Ok(websocket)
    }

    async fn heartbeat(
        ping_pong_tx: Sender<PingPong>,
        mut pong_rx: Receiver<()>,
        interval: Duration,
    ) -> anyhow::Result<()> {
        let mut interval_stream = IntervalStream::new(tokio_time::interval(interval));
        while (interval_stream.next().await).is_some() {
            if let Err(err) = ping_pong_tx.send_async(PingPong::Ping).await {
                error!(%err, "websocket stopped");

                return Err(anyhow::anyhow!("websocket stopped"));
            }

            let sleep_fut = tokio_time::sleep(interval);

            tokio::select! {
                _ = sleep_fut => {
                    error!("websocket heartbeat timeout");

                    return Err(anyhow::anyhow!("websocket heartbeat timeout"))
                }

                result = pong_rx.next() => {
                    if result.is_none() {
                        error!("websocket stopped");

                        return Err(anyhow::anyhow!("websocket stopped"))
                    }
                }
            }
        }

        Err(anyhow::anyhow!("heartbeat timer stopped"))
    }

    async fn run_transport(
        websocket: WebSocketStream<MaybeTlsStream<TcpStream>>,
        tun_sender: Sender<TunMessage>,
        mailbox: Receiver<Message>,
        heartbeat_interval: Duration,
    ) {
        let (transport_tx, transport_rx) = websocket.split();

        let mut join_set = JoinSet::new();
        let (ping_pong_tx, ping_pong_rx) = flume::unbounded();
        let ping_pong_tx_clone = ping_pong_tx.clone();
        let (pong_tx, pong_rx) = flume::unbounded();

        join_set.spawn(async move {
            Self::transport_to_tun(transport_rx, tun_sender, ping_pong_tx_clone, pong_tx).await
        });

        join_set.spawn(async move {
            Self::tun_to_transport(transport_tx, mailbox, ping_pong_rx.into_stream()).await
        });

        join_set.spawn(async move {
            Self::heartbeat(ping_pong_tx, pong_rx.into_stream(), heartbeat_interval).await
        });

        if let Err(err) = join_set.join_next().await.unwrap().unwrap() {
            error!(%err, "transport stopped with error");
        } else {
            info!("transport stopped");
        }

        join_set.shutdown().await;
    }

    async fn transport_to_tun(
        mut transport_rx: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        tun_sender: Sender<TunMessage>,
        ping_pong_tx: Sender<PingPong>,
        pong_tx: Sender<()>,
    ) -> anyhow::Result<()> {
        while let Some(ws_message) = transport_rx
            .try_next()
            .await
            .tap_err(|err| error!(%err, "receive packet from transport rx failed"))?
        {
            let packet = match ws_message {
                tungstenite::Message::Binary(packet) => Bytes::from(packet),

                tungstenite::Message::Ping(_) => {
                    ping_pong_tx
                        .send_async(PingPong::Pong)
                        .await
                        .tap_err(|err| error!(%err, "notify send pong failed"))?;

                    continue;
                }

                tungstenite::Message::Pong(_) => {
                    pong_tx
                        .send_async(())
                        .await
                        .tap_err(|err| error!(%err, "heartbeat stopped"))?;

                    continue;
                }

                tungstenite::Message::Close(_) => {
                    info!("websocket close message received");

                    return Ok(());
                }

                ws_message => {
                    error!(%ws_message, "receive unexpected websocket message");

                    return Err(anyhow::anyhow!(
                        "receive unexpected websocket message: {ws_message}"
                    ));
                }
            };

            if packet.is_empty() {
                break;
            }

            match tun_sender.try_send(TunMessage::ToTun(packet)) {
                Err(TrySendError::Full(_)) => {
                    warn!("tun mailbox is full, drop packet");

                    continue;
                }

                Err(err) => {
                    error!(%err, "send packet failed");

                    return Err(err.into());
                }

                Ok(_) => {}
            }
        }

        Ok(())
    }

    async fn tun_to_transport(
        mut transport_tx: SplitSink<
            WebSocketStream<MaybeTlsStream<TcpStream>>,
            tungstenite::Message,
        >,
        mut mailbox: Receiver<Message>,
        mut ping_pong_rx: Receiver<PingPong>,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                packet = mailbox.next() => {
                    match packet {
                        None => {
                            return Err(anyhow::anyhow!("websocket_transport_receiver stopped"));
                        }

                        Some(Message::Packet(packet)) => {
                            transport_tx
                            .send(tungstenite::Message::Binary(packet.into()))
                            .await
                            .tap_err(|err|error!(%err, "transport tx send failed"))?;
                        }
                    }
                }

                ping_pong = ping_pong_rx.next() => {
                    let ping_pong_message = match ping_pong {
                        None => {
                            return Err(anyhow::anyhow!("websocket ping stopped"));
                        }

                        Some(PingPong::Pong) => tungstenite::Message::Pong(vec![]),
                        Some(PingPong::Ping) => tungstenite::Message::Ping(vec![])
                    };

                    transport_tx
                        .send(ping_pong_message)
                        .await
                        .tap_err(|err|error!(%err, "transport tx send failed"))?;
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PingPong {
    Ping,
    Pong,
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use bytes::Bytes;
    use http::Request;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::upgrade::Upgraded;
    use hyper::{Body, Server};
    use rustls::{Certificate, PrivateKey, ServerConfig};
    use test_log::test;
    use tokio::fs;
    use tokio::net::TcpListener;

    use super::*;
    use crate::tls_accept::TlsAcceptor;

    #[test(tokio::test)]
    async fn test() {
        const TEST_SECRET: &str = "testtesttesttest";
        const HEARTBEAT: Duration = Duration::from_secs(5);
        const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12010);
        const PUBLIC_ID: &str = "public id";

        let token_generator = TokenGenerator::new(TEST_SECRET.to_string(), None).unwrap();
        let token_generator_clone = token_generator.clone();
        let tls_server_config = create_tls_server_config().await.unwrap();

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config));
        let tcp_listener = TcpListener::bind(LISTEN_ADDR).await.unwrap();
        let tls_acceptor = TlsAcceptor::new(tcp_listener, tls_acceptor);

        let builder = Server::builder(tls_acceptor);

        let (body_tx, body_rx) = flume::bounded(1);

        tokio::spawn(async move {
            builder
                .serve(make_service_fn(move |_conn| {
                    let body_tx = body_tx.clone();
                    let token_generator_clone = token_generator_clone.clone();

                    future::ready(Ok::<_, Infallible>(service_fn(
                        move |req: Request<Body>| {
                            let body_tx = body_tx.clone();
                            let token_generator_clone = token_generator_clone.clone();

                            async move {
                                assert!(hyper_tungstenite::is_upgrade_request(&req));

                                let hmac =
                                    req.headers().get(HMAC_HEADER).unwrap().to_str().unwrap();
                                assert_eq!(token_generator_clone.generate_token(), hmac);

                                let public_id = req
                                    .headers()
                                    .get(PUBLIC_ID_HEADER)
                                    .unwrap()
                                    .to_str()
                                    .unwrap();
                                assert_eq!(public_id, PUBLIC_ID);

                                let (resp, websocket) =
                                    hyper_tungstenite::upgrade(req, None).unwrap();

                                tokio::spawn(async move {
                                    let mut websocket: WebSocketStream<Upgraded> =
                                        websocket.await.unwrap();
                                    websocket
                                        .send(tungstenite::Message::Binary(b"test".to_vec()))
                                        .await
                                        .unwrap();

                                    if let tungstenite::Message::Binary(data) =
                                        websocket.try_next().await.unwrap().unwrap()
                                    {
                                        body_tx.send_async(data).await.unwrap()
                                    } else {
                                        panic!("not binary")
                                    }
                                });

                                Ok::<_, Infallible>(resp)
                            }
                        },
                    )))
                }))
                .await
        });

        let (websocket_transport_sender, websocket_transport_mailbox) = flume::unbounded();
        let (tun_sender, tun_mailbox) = flume::unbounded();
        let mut websocket_transport_actor = WebsocketTransportActor::new(
            Some("../testdata/ca.cert"),
            "wss://localhost:12010".to_string(),
            PUBLIC_ID.to_string(),
            token_generator,
            HEARTBEAT,
            websocket_transport_mailbox.into_stream(),
            tun_sender,
        )
        .await
        .unwrap();

        tokio::spawn(async move { websocket_transport_actor.run().await });

        websocket_transport_sender
            .send_async(Message::Packet(Bytes::from_static(b"test")))
            .await
            .unwrap();

        let TunMessage::ToTun(tun_packet) = tun_mailbox.recv_async().await.unwrap();
        assert_eq!(tun_packet.as_ref(), b"test");
        let body = body_rx.recv_async().await.unwrap();
        assert_eq!(body, b"test");
    }

    async fn create_tls_server_config() -> anyhow::Result<ServerConfig> {
        let mut keys = load_keys().await?;
        let certs = load_certs().await?;

        Ok(ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))?)
    }

    async fn load_certs() -> anyhow::Result<Vec<Certificate>> {
        let certs = fs::read("../testdata/server.cert").await?;
        let mut certs = rustls_pemfile::certs(&mut certs.as_slice())?;

        Ok(certs.drain(..).map(Certificate).collect())
    }

    async fn load_keys() -> anyhow::Result<Vec<PrivateKey>> {
        let keys = fs::read("../testdata/server.key").await?;
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut keys.as_slice())?;

        Ok(keys.drain(..).map(PrivateKey).collect())
    }
}
