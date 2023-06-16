use std::convert::Infallible;
use std::future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use flume::{Sender, TrySendError};
use futures_util::{StreamExt, TryStreamExt};
use http::{Method, Request, Response, StatusCode, Version};
use hyper::server::Builder;
use hyper::service::{make_service_fn, service_fn};
use hyper::{body, Body, Server};
use rustls::{Certificate, PrivateKey, ServerConfig};
use tap::{TapFallible, TapOptional};
use tokio::fs;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, error, info, instrument, warn};

pub use self::auth::AuthStore;
use super::message::Http2Message as Message;
use super::message::TunMessage;
use super::peer_store::PeerStore;
use crate::ip_packet::{get_packet_ip, IpLocation};
use crate::tls_accept::TlsAcceptor;
use crate::util::{
    Receiver, HMAC_HEADER, INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE,
    PUBLIC_ID_HEADER,
};

mod auth;

pub struct Http2TransportActor {
    inner: Arc<Http2TransportActorInner>,
    builder: Option<Builder<TlsAcceptor>>,
}

#[derive(Debug)]
struct Http2TransportActorInner {
    tun_sender: Sender<TunMessage>,

    auth_store: AuthStore,
    peer_store: PeerStore,
}

impl Http2TransportActorInner {
    #[instrument]
    async fn handle(&self, request: Request<Body>) -> Response<Body> {
        debug!(?request, "accept new http request");

        if request.version() != Version::HTTP_2 {
            error!("reject not http2 request");

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::UNAUTHORIZED;

            return response;
        }

        let public_id = match self.auth_token(&request) {
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::UNAUTHORIZED;

                return response;
            }

            Some(public_id) => public_id,
        };

        let method = request.method();
        if method != Method::POST {
            error!(%method, "reject not POST method http2 request");

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::UNAUTHORIZED;

            return response;
        }

        info!("http2 auth done");

        let public_id = public_id.to_string();
        let body = request.into_body();
        let (body_sender, response_body) = Body::channel();
        let response = Response::new(response_body);

        let tun_sender = self.tun_sender.clone();
        let peer_store = self.peer_store.clone();

        tokio::spawn(Self::run_transport(
            body_sender,
            body,
            public_id,
            tun_sender,
            peer_store,
        ));

        response
    }

    async fn run_transport(
        transport_tx: body::Sender,
        transport_rx: Body,
        public_id: String,
        tun_sender: Sender<TunMessage>,
        peer_store: PeerStore,
    ) {
        let http2_transport_receiver = peer_store
            .get_http2_transport_receiver_by_public_id(&public_id)
            .expect("handshake done public id has no http2 transport receiver");
        let mut join_set = JoinSet::new();

        join_set.spawn(async move {
            Self::transport_to_tun(transport_rx, tun_sender, peer_store, public_id).await
        });

        join_set.spawn(async move {
            Self::tun_to_transport(transport_tx, http2_transport_receiver).await
        });

        if let Err(err) = join_set.join_next().await.unwrap().unwrap() {
            error!(%err, "run transport failed");
        } else {
            error!("run transport stopped");
        }
    }

    async fn transport_to_tun(
        mut transport_rx: Body,
        tun_sender: Sender<TunMessage>,
        peer_store: PeerStore,
        public_id: String,
    ) -> anyhow::Result<()> {
        while let Some(packet) = transport_rx
            .try_next()
            .await
            .tap_err(|err| error!(%err, "receive packet from transport rx failed"))?
        {
            if packet.is_empty() {
                break;
            }

            match get_packet_ip(&packet, IpLocation::Src) {
                None => {
                    warn!("drop not ip packet");

                    continue;
                }

                Some(src_ip) => {
                    if let IpAddr::V6(src_ip) = src_ip {
                        if src_ip.is_unicast_link_local() {
                            peer_store.update_link_local_ip(src_ip, &public_id);
                        }
                    }
                }
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
        mut transport_tx: body::Sender,
        mut http2_transport_receiver: Receiver<Message>,
    ) -> anyhow::Result<()> {
        while let Some(Message::Packet(packet)) = http2_transport_receiver.next().await {
            transport_tx
                .send_data(packet)
                .await
                .tap_err(|err| error!(%err, "transport tx send failed"))?;
        }

        Err(anyhow::anyhow!("http2_transport_receiver stopped"))
    }

    #[instrument]
    fn auth_token<'a>(&self, request: &'a Request<Body>) -> Option<&'a str> {
        let hmac = match request.headers().get(HMAC_HEADER) {
            None => {
                error!("the h2 request doesn't have hmac header, reject it");

                return None;
            }

            Some(hmac) => match hmac.to_str() {
                Err(err) => {
                    error!(%err, "hmac is not valid utf8 string");

                    return None;
                }

                Ok(hmac) => hmac,
            },
        };

        let public_id = match request.headers().get(PUBLIC_ID_HEADER) {
            None => {
                error!("the h2 request doesn't have public id header, reject it");

                return None;
            }

            Some(public_id) => match public_id.to_str() {
                Err(err) => {
                    error!(%err, "public id is not valid utf8 string");

                    return None;
                }

                Ok(public_id) => public_id,
            },
        };

        self.auth_store
            .auth(public_id, hmac)
            .then_some(public_id)
            .tap_none(|| error!(public_id, hmac, "auth failed"))
    }
}

impl Http2TransportActor {
    pub async fn new(
        tun_sender: Sender<TunMessage>,
        auth_store: AuthStore,
        peer_store: PeerStore,
        listen_addr: SocketAddr,
        cert: &str,
        key: &str,
        heartbeat_interval: Duration,
    ) -> anyhow::Result<Self> {
        let certs = load_certs(cert).await?;
        let mut keys = load_keys(key).await?;

        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))?;

        info!("create server config done");

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let tcp_listener = TcpListener::bind(listen_addr).await?;
        let tls_acceptor = TlsAcceptor::new(tcp_listener, tls_acceptor);

        let builder = Server::builder(tls_acceptor)
            .http2_initial_stream_window_size(INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .http2_max_frame_size(MAX_FRAME_SIZE)
            .http2_keep_alive_timeout(heartbeat_interval)
            .http2_keep_alive_interval(heartbeat_interval);

        let inner = Arc::new(Http2TransportActorInner {
            tun_sender,
            auth_store,
            peer_store,
        });

        Ok(Self {
            inner,
            builder: Some(builder),
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let inner = self.inner.clone();

        let builder = self.builder.take().expect("server has been stopped");

        info!("start http2 transport actor");

        builder
            .serve(make_service_fn(move |_conn| {
                let inner = inner.clone();

                future::ready(Ok::<_, Infallible>(service_fn(move |req| {
                    let inner = inner.clone();

                    async move { Ok::<_, Infallible>(inner.handle(req).await) }
                })))
            }))
            .await?;

        Err(anyhow::anyhow!("http2 transport stopped"))
    }
}

async fn load_certs(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let certs = fs::read(path).await?;
    let mut certs = rustls_pemfile::certs(&mut certs.as_slice())?;

    Ok(certs.drain(..).map(Certificate).collect())
}

async fn load_keys(path: &str) -> anyhow::Result<Vec<PrivateKey>> {
    let keys = fs::read(path).await?;
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut keys.as_slice())?;

    Ok(keys.drain(..).map(PrivateKey).collect())
}
