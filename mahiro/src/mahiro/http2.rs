use std::time::Duration;

use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::{StreamExt, TryStreamExt};
use http::{Method, Request, StatusCode, Uri, Version};
use hyper::client::HttpConnector;
use hyper::{body, Body, Client};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use tap::TapFallible;
use tokio::task::JoinSet;
use tracing::{error, info, instrument};

use super::message::TransportMessage as Message;
use super::message::TunMessage;
use crate::token::TokenGenerator;
use crate::util;
use crate::util::{
    Receiver, HMAC_HEADER, HTTP2_TRANSPORT_COUNT, INITIAL_CONNECTION_WINDOW_SIZE,
    INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PUBLIC_ID_HEADER,
};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Http2TransportActor {
    #[derivative(Debug = "ignore")]
    mailbox: Receiver<Message>,
    tun_sender: Sender<TunMessage>,

    client: Client<HttpsConnector<HttpConnector>>,
    remote_url: Uri,
    public_id: String,
    token_generator: TokenGenerator,
    heartbeat_interval: Duration,
    transport_count: u8,
}

impl Http2TransportActor {
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
        let remote_domain = remote_url.host().ok_or_else(|| {
            error!(%remote_url, "no host found");

            anyhow::anyhow!("no host found")
        })?;

        let client_config = util::create_tls_client_config(None, ca).await?;
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .with_server_name(remote_domain.to_string())
            .enable_http2()
            .build();

        let client = Client::builder()
            .http2_only(true)
            .http2_initial_connection_window_size(INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .http2_max_frame_size(MAX_FRAME_SIZE)
            .http2_keep_alive_timeout(heartbeat_interval)
            .http2_keep_alive_interval(heartbeat_interval)
            .build(https_connector);

        Ok(Self {
            mailbox,
            tun_sender,
            client,
            remote_url,
            public_id,
            token_generator,
            heartbeat_interval,
            transport_count: HTTP2_TRANSPORT_COUNT,
        })
    }

    pub async fn run(&mut self) {
        loop {
            if let Err(err) = self.run_circle().await {
                error!(%err, "http2 actor run circle failed");
            }
        }
    }

    async fn run_circle(&mut self) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();

        for _ in 0..self.transport_count {
            let (body, sender) = self
                .open_transport()
                .await
                .tap_err(|err| error!(%err, "open transport failed"))?;
            let mailbox = self.mailbox.clone();
            let tun_sender = self.tun_sender.clone();

            join_set
                .spawn(async move { Self::run_transport(body, sender, tun_sender, mailbox).await });
        }

        join_set.join_next().await.unwrap().unwrap();

        Err(anyhow::anyhow!("http2 actor stopped"))
    }

    #[instrument(err)]
    async fn open_transport(&self) -> anyhow::Result<(Body, body::Sender)> {
        let hmac = self.token_generator.generate_token();

        let (sender, body) = Body::channel();

        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri(self.remote_url.clone())
            .method(Method::POST)
            .header(PUBLIC_ID_HEADER, &self.public_id)
            .header(HMAC_HEADER, &hmac)
            .body(body)
            .tap_err(|err| {
                error!(%err, %hmac, "build h2 request failed");
            })?;

        let response = self
            .client
            .request(request)
            .await
            .tap_err(|err| error!(%err, %hmac, "send h2 request failed"))?;

        info!(%hmac, "receive h2 response done");

        if response.status() != StatusCode::OK {
            let status_code = response.status();
            error!(%status_code, %hmac, "status code is not 200");

            return Err(anyhow::anyhow!("status code is not 200"));
        }

        info!(%hmac, "get h2 stream done");

        Ok((response.into_body(), sender))
    }

    async fn run_transport(
        mut transport_rx: Body,
        mut transport_tx: body::Sender,
        tun_sender: Sender<TunMessage>,
        mut mailbox: Receiver<Message>,
    ) {
        let mut join_set = JoinSet::new();
        join_set.spawn(async move {
            while let Some(data) = transport_rx
                .try_next()
                .await
                .tap_err(|err| error!(%err, "transport rx failed"))?
            {
                if data.is_empty() {
                    break;
                }

                if let Err(TrySendError::Disconnected(_)) =
                    tun_sender.try_send(TunMessage::ToTun(data))
                {
                    error!("tun sender disconnected");

                    return Err(anyhow::anyhow!("tun sender disconnected"));
                }
            }

            Ok(())
        });

        join_set.spawn(async move {
            while let Some(Message::Packet(packet)) = mailbox.next().await {
                transport_tx
                    .send_data(packet)
                    .await
                    .tap_err(|err| error!(%err, "transport tx send failed"))?;
            }

            Ok(())
        });

        if let Err(err) = join_set.join_next().await.unwrap().unwrap() {
            error!(%err, "transport stopped with error");
        } else {
            info!("transport stopped");
        }

        join_set.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use bytes::Bytes;
    use http::Response;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::Server;
    use rustls::{Certificate, PrivateKey, ServerConfig};
    use tokio::fs;
    use tokio::net::TcpListener;

    use super::*;
    use crate::tls_accept::TlsAcceptor;

    #[tokio::test]
    async fn test() {
        const TEST_SECRET: &str = "testtesttesttest";
        const HEARTBEAT: Duration = Duration::from_secs(5);
        const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12001);
        const PUBLIC_ID: &str = "public id";

        let token_generator = TokenGenerator::new(TEST_SECRET.to_string(), None).unwrap();
        let token_generator_clone = token_generator.clone();
        let tls_server_config = create_tls_server_config().await.unwrap();

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config));
        let tcp_listener = TcpListener::bind(LISTEN_ADDR).await.unwrap();
        let tls_acceptor = TlsAcceptor::new(tcp_listener, tls_acceptor);

        let builder = Server::builder(tls_acceptor)
            .http2_initial_stream_window_size(INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .http2_max_frame_size(MAX_FRAME_SIZE)
            .http2_keep_alive_timeout(HEARTBEAT)
            .http2_keep_alive_interval(HEARTBEAT);

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
                                assert_eq!(req.version(), Version::HTTP_2);

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

                                let mut body = req.into_body();
                                let (mut sender, resp_body) = Body::channel();
                                sender.try_send_data(Bytes::from_static(b"test")).unwrap();

                                tokio::spawn(async move {
                                    let data = body.next().await.unwrap().unwrap();
                                    body_tx.send_async(data).await.unwrap();
                                });

                                Ok::<_, Infallible>(Response::new(resp_body))
                            }
                        },
                    )))
                }))
                .await
        });

        let (http2_transport_sender, http2_transport_mailbox) = flume::unbounded();
        let (tun_sender, tun_mailbox) = flume::unbounded();
        let mut http2transport_actor = Http2TransportActor::new(
            Some("../testdata/ca.cert"),
            "https://localhost:12001".to_string(),
            PUBLIC_ID.to_string(),
            token_generator,
            HEARTBEAT,
            http2_transport_mailbox.into_stream(),
            tun_sender,
        )
        .await
        .unwrap();

        tokio::spawn(async move { http2transport_actor.run().await });

        http2_transport_sender
            .send_async(Message::Packet(Bytes::from_static(b"test")))
            .await
            .unwrap();

        let TunMessage::ToTun(tun_packet) = tun_mailbox.recv_async().await.unwrap();
        assert_eq!(tun_packet.as_ref(), b"test");
        let body = body_rx.recv_async().await.unwrap();
        assert_eq!(body.as_ref(), b"test");
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
