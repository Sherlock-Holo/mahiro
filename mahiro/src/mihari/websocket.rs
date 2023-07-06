use std::convert::Infallible;
use std::fmt::Debug;
use std::future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use flume::{Sender, TrySendError};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use http::{Request, Response, StatusCode};
use hyper::server::Builder;
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Server};
use hyper_tungstenite::{tungstenite, HyperWebsocket, WebSocketStream};
use rustls::ServerConfig;
use tap::{TapFallible, TapOptional};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time as tokio_time;
use tokio_stream::wrappers::IntervalStream;
use tracing::{debug, error, info, instrument, warn};

use super::message::TransportMessage as Message;
use super::message::TunMessage;
use super::peer_store::PeerStore;
use crate::ip_packet::{get_packet_ip, IpLocation};
use crate::tls_accept::TlsAcceptor;
use crate::token::AuthStore;
use crate::util;
use crate::util::{Receiver, HMAC_HEADER, PUBLIC_ID_HEADER};

pub struct WebsocketTransportActor<T: Send + Sync + Debug + Clone> {
    inner: Arc<WebsocketTransportActorInner<T>>,
    builder: Option<Builder<TlsAcceptor>>,
}

#[derive(Debug)]
struct WebsocketTransportActorInner<T: Send + Sync + Debug + Clone> {
    tun_sender: Sender<TunMessage>,

    auth_store: AuthStore,
    peer_store: PeerStore<T>,
    heartbeat_interval: Duration,
}

impl<T: Send + Sync + Debug + Clone + 'static> WebsocketTransportActorInner<T> {
    #[instrument]
    async fn handle(&self, request: Request<Body>) -> Response<Body> {
        debug!(?request, "accept new http request");

        if !hyper_tungstenite::is_upgrade_request(&request) {
            error!("reject not websocket request");

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

        info!(public_id, "websocket auth done");

        let public_id = public_id.to_string();

        let (response, websocket) = match hyper_tungstenite::upgrade(request, None) {
            Err(err) => {
                error!(%err, public_id, "websocket upgrade failed");

                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::UNAUTHORIZED;

                return response;
            }

            Ok(resp) => resp,
        };

        info!(public_id, "websocket handshake done");

        let tun_sender = self.tun_sender.clone();
        let peer_store = self.peer_store.clone();

        tokio::spawn(Self::run_transport(
            websocket,
            public_id,
            tun_sender,
            peer_store,
            self.heartbeat_interval,
        ));

        response
    }

    async fn run_transport(
        websocket: HyperWebsocket,
        public_id: String,
        tun_sender: Sender<TunMessage>,
        peer_store: PeerStore<T>,
        heartbeat_interval: Duration,
    ) {
        let websocket = match websocket.await {
            Err(err) => {
                error!(%err, "websocket upgrade failed");

                return;
            }

            Ok(websocket) => websocket,
        };

        let (transport_tx, transport_rx) = websocket.split();

        let transport_receiver = peer_store
            .get_transport_receiver_by_identity(&public_id)
            .expect("handshake done public id has no websocket transport receiver");

        let mut join_set = JoinSet::new();
        let (ping_pong_tx, ping_pong_rx) = flume::unbounded();
        let ping_pong_tx_clone = ping_pong_tx.clone();
        let (pong_tx, pong_rx) = flume::unbounded();

        join_set.spawn(async move {
            Self::transport_to_tun(
                transport_rx,
                tun_sender,
                ping_pong_tx_clone,
                pong_tx,
                peer_store,
                public_id,
            )
            .await
        });

        join_set.spawn(async move {
            Self::tun_to_transport(transport_tx, transport_receiver, ping_pong_rx.into_stream())
                .await
        });

        join_set.spawn(async move {
            Self::heartbeat(ping_pong_tx, pong_rx.into_stream(), heartbeat_interval).await
        });

        if let Err(err) = join_set.join_next().await.unwrap().unwrap() {
            error!(%err, "run transport failed");
        } else {
            error!("run transport stopped");
        }
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

    async fn transport_to_tun(
        mut transport_rx: SplitStream<WebSocketStream<Upgraded>>,
        tun_sender: Sender<TunMessage>,
        ping_pong_tx: Sender<PingPong>,
        pong_tx: Sender<()>,
        peer_store: PeerStore<T>,
        public_id: String,
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
        mut transport_tx: SplitSink<WebSocketStream<Upgraded>, tungstenite::Message>,
        mut websocket_transport_receiver: Receiver<Message>,
        mut ping_pong_rx: Receiver<PingPong>,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                packet = websocket_transport_receiver.next() => {
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

impl<T: Send + Sync + Debug + Clone + 'static> WebsocketTransportActor<T> {
    pub async fn new(
        tun_sender: Sender<TunMessage>,
        auth_store: AuthStore,
        peer_store: PeerStore<T>,
        listen_addr: SocketAddr,
        cert: &str,
        key: &str,
        heartbeat_interval: Duration,
    ) -> anyhow::Result<Self> {
        let certs = util::load_certs(cert).await?;
        let mut keys = util::load_keys(key).await?;

        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))?;

        info!("create server config done");

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let tcp_listener = TcpListener::bind(listen_addr).await?;
        let tls_acceptor = TlsAcceptor::new(tcp_listener, tls_acceptor);
        let builder = Server::builder(tls_acceptor);

        let inner = Arc::new(WebsocketTransportActorInner {
            tun_sender,
            auth_store,
            peer_store,
            heartbeat_interval,
        });

        Ok(Self {
            inner,
            builder: Some(builder),
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let inner = self.inner.clone();

        let builder = self.builder.take().expect("server has been stopped");

        info!("start websocket transport actor");

        builder
            .serve(make_service_fn(move |_conn| {
                let inner = inner.clone();

                future::ready(Ok::<_, Infallible>(service_fn(move |req| {
                    let inner = inner.clone();

                    async move { Ok::<_, Infallible>(inner.handle(req).await) }
                })))
            }))
            .await?;

        Err(anyhow::anyhow!("websocket transport stopped"))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PingPong {
    Ping,
    Pong,
}
