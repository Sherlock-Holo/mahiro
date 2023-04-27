use std::str::FromStr;

use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use once_cell::sync::Lazy;
use snow::params::NoiseParams;
use snow::Builder;
use thiserror::Error;
use tracing::{error, info, instrument};

static NOISE_PARAMS: Lazy<NoiseParams> =
    Lazy::new(|| NoiseParams::from_str("Noise_IX_25519_ChaChaPoly_BLAKE2s").unwrap());

#[derive(Debug, Error)]
pub enum Error {
    #[error("init encrypt error: {0}")]
    InitEncryptError(snow::Error),

    #[error("handshake error: {0}")]
    HandshakeError(snow::Error),

    #[error("convert into transport mode error: {0}")]
    IntoTransportError(snow::Error),

    #[error("encrypt failed: {0}")]
    EncryptError(snow::Error),

    #[error("decrypt failed: {0}")]
    DecryptError(snow::Error),
}

#[derive(Debug)]
pub enum HandshakeState {
    Failed(snow::Error),
    MissPeerPublicKey,
    PeerPublicKey(Bytes),
}

#[derive(Debug)]
enum State {
    Handshake(Box<snow::HandshakeState>),
    Transport(snow::StatelessTransportState),
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Encrypt {
    state: State,
    #[derivative(Debug = "ignore")]
    buffer: BytesMut,
}

impl Encrypt {
    pub fn new(local_private_key: &[u8]) -> Result<Self, Error> {
        const BUFFER_SIZE: usize = 65535;

        let state = Builder::new(NOISE_PARAMS.clone())
            .local_private_key(local_private_key)
            .build_responder()
            .map_err(Error::InitEncryptError)?;

        Ok(Self {
            state: State::Handshake(Box::new(state)),
            buffer: BytesMut::zeroed(BUFFER_SIZE),
        })
    }

    #[instrument(err)]
    pub fn into_transport_mode(self) -> Result<Self, Error> {
        match self.state {
            State::Handshake(state) => {
                let transport_state = state.into_stateless_transport_mode().map_err(|err| {
                    error!(%err, "convert transport mode failed");

                    Error::IntoTransportError(err)
                })?;

                Ok(Self {
                    state: State::Transport(transport_state),
                    buffer: self.buffer,
                })
            }
            State::Transport(_) => {
                panic!("call into_transport_mode after into_transport_mode done");
            }
        }
    }

    #[instrument(skip(data), err)]
    pub fn encrypt(&mut self, nonce: u64, data: &[u8]) -> Result<Bytes, Error> {
        match &mut self.state {
            State::Handshake(_) => {
                unreachable!("call encrypt before handshake");
            }
            State::Transport(state) => {
                let n = state
                    .write_message(nonce, data, &mut self.buffer)
                    .map_err(|err| {
                        error!(%err, "encrypt data failed");

                        Error::EncryptError(err)
                    })?;

                Ok(Bytes::from(self.buffer[..n].to_vec()))
            }
        }
    }

    #[instrument(skip(data), err)]
    pub fn decrypt(&mut self, nonce: u64, data: &[u8]) -> Result<Bytes, Error> {
        match &mut self.state {
            State::Handshake(_) => {
                unreachable!("call decrypt before handshake");
            }
            State::Transport(state) => {
                let n = state
                    .read_message(nonce, data, &mut self.buffer)
                    .map_err(|err| {
                        error!(%err, "decrypt data failed");

                        Error::DecryptError(err)
                    })?;

                Ok(Bytes::from(self.buffer[..n].to_vec()))
            }
        }
    }
}

impl Encrypt {
    pub fn initiator_handshake(&mut self) -> Result<Bytes, Error> {
        match &mut self.state {
            State::Handshake(state) => {
                let n = state.write_message(&[], &mut self.buffer).map_err(|err| {
                    error!(%err, "get initiator handshake data failed");

                    Error::HandshakeError(err)
                })?;

                Ok(Bytes::from(self.buffer[..n].to_vec()))
            }
            State::Transport(_) => {
                unreachable!("call initiator_handshake after initiator_handshake done");
            }
        }
    }

    pub fn initiator_handshake_response(&mut self, data: &[u8]) -> HandshakeState {
        match &mut self.state {
            State::Handshake(handshake) => match handshake.read_message(data, &mut self.buffer) {
                Err(err) => {
                    error!(%err, "initiator handshake failed");

                    HandshakeState::Failed(err)
                }

                Ok(_) => {
                    info!("initiator handshake done");

                    match handshake.get_remote_static() {
                        None => {
                            error!("miss peer public key");

                            HandshakeState::MissPeerPublicKey
                        }

                        Some(public_key) => {
                            HandshakeState::PeerPublicKey(Bytes::from(public_key.to_vec()))
                        }
                    }
                }
            },

            State::Transport(_) => {
                unreachable!(
                    "call initiator_handshake_response after initiator_handshake_response done"
                );
            }
        }
    }
}

impl Encrypt {
    #[instrument(skip(data))]
    pub fn responder_handshake(&mut self, data: &[u8]) -> HandshakeState {
        match &mut self.state {
            State::Handshake(handshake) => match handshake.read_message(data, &mut self.buffer) {
                Err(err) => {
                    error!(%err, "responder handshake failed");

                    HandshakeState::Failed(err)
                }

                Ok(_) => {
                    info!("responder handshake done");

                    match handshake.get_remote_static() {
                        None => {
                            error!("miss peer public key");

                            HandshakeState::MissPeerPublicKey
                        }

                        Some(public_key) => {
                            HandshakeState::PeerPublicKey(Bytes::from(public_key.to_vec()))
                        }
                    }
                }
            },

            State::Transport(_) => {
                unreachable!("call responder_handshake after responder_handshake done");
            }
        }
    }

    #[instrument(err)]
    pub fn responder_handshake_response(&mut self) -> Result<Bytes, Error> {
        match &mut self.state {
            State::Handshake(state) => {
                let n = state.write_message(&[], &mut self.buffer).map_err(|err| {
                    error!(%err, "get responder handshake response data failed");

                    Error::HandshakeError(err)
                })?;

                let data = Bytes::from(self.buffer[..n].to_vec());

                Ok(data)
            }
            State::Transport(_) => {
                unreachable!("call handshake_response after handshake done");
            }
        }
    }
}
