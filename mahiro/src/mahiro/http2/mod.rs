use std::time::Duration;

use derivative::Derivative;
use flume::{Sender, TrySendError};
use futures_util::{StreamExt, TryStreamExt};
use http::{Method, Request, StatusCode, Uri, Version};
use hyper::client::HttpConnector;
use hyper::{body, Body, Client};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::ClientConfig;
use tap::TapFallible;
use tokio::task::JoinSet;
use tracing::{error, info, instrument};

use super::message::Http2Message as Message;
use super::message::TunMessage;
use crate::token::TokenGenerator;
use crate::util::{
    Receiver, HMAC_HEADER, INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE,
    PUBLIC_ID_HEADER, TRANSPORT_COUNT,
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
    pub fn new(
        client_config: ClientConfig,
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
            transport_count: TRANSPORT_COUNT,
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
