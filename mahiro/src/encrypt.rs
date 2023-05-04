use std::str::FromStr;

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
    InitEncrypt(snow::Error),

    #[error("handshake error: {0}")]
    Handshake(snow::Error),

    #[error("convert into transport mode error: {0}")]
    IntoTransport(snow::Error),

    #[error("encrypt failed: {0}")]
    Encrypt(snow::Error),

    #[error("decrypt failed: {0}")]
    Decrypt(snow::Error),
}

#[derive(Debug)]
pub enum HandshakeState<'a> {
    Failed(snow::Error),
    MissPeerPublicKey,
    PeerPublicKey(&'a [u8]),
}

#[derive(Debug)]
enum State {
    Handshake(Box<snow::HandshakeState>, Vec<u8>),
    Transport(snow::StatelessTransportState),
}

#[derive(Debug)]
pub struct Encrypt {
    state: State,
}

impl Encrypt {
    pub fn new_initiator(local_private_key: &[u8]) -> Result<Self, Error> {
        const BUFFER_SIZE: usize = 65535;

        let state = Builder::new(NOISE_PARAMS.clone())
            .local_private_key(local_private_key)
            .build_initiator()
            .map_err(Error::InitEncrypt)?;

        Ok(Self {
            state: State::Handshake(Box::new(state), vec![0; BUFFER_SIZE]),
        })
    }

    pub fn new_responder(local_private_key: &[u8]) -> Result<Self, Error> {
        const BUFFER_SIZE: usize = 65535;

        let state = Builder::new(NOISE_PARAMS.clone())
            .local_private_key(local_private_key)
            .build_responder()
            .map_err(Error::InitEncrypt)?;

        Ok(Self {
            state: State::Handshake(Box::new(state), vec![0; BUFFER_SIZE]),
        })
    }

    #[instrument(err)]
    pub fn into_transport_mode(self) -> Result<Self, Error> {
        match self.state {
            State::Handshake(state, _) => {
                let transport_state = state.into_stateless_transport_mode().map_err(|err| {
                    error!(%err, "convert transport mode failed");

                    Error::IntoTransport(err)
                })?;

                Ok(Self {
                    state: State::Transport(transport_state),
                })
            }
            State::Transport(_) => {
                panic!("call into_transport_mode after into_transport_mode done");
            }
        }
    }

    #[instrument(skip(data, buffer), err)]
    pub fn encrypt(&self, nonce: u64, data: &[u8], buffer: &mut [u8]) -> Result<usize, Error> {
        match &self.state {
            State::Handshake(_, _) => {
                unreachable!("call encrypt before handshake");
            }
            State::Transport(state) => {
                let n = state.write_message(nonce, data, buffer).map_err(|err| {
                    error!(%err, "encrypt data failed");

                    Error::Encrypt(err)
                })?;

                Ok(n)
            }
        }
    }

    #[instrument(skip(data, buffer), err)]
    pub fn decrypt(&self, nonce: u64, data: &[u8], buffer: &mut [u8]) -> Result<usize, Error> {
        match &self.state {
            State::Handshake(_, _) => {
                unreachable!("call decrypt before handshake");
            }
            State::Transport(state) => {
                let n = state.read_message(nonce, data, buffer).map_err(|err| {
                    error!(%err, "decrypt data failed");

                    Error::Decrypt(err)
                })?;

                Ok(n)
            }
        }
    }
}

impl Encrypt {
    pub fn initiator_handshake(&mut self) -> Result<&[u8], Error> {
        match &mut self.state {
            State::Handshake(state, buffer) => {
                let n = state.write_message(&[], buffer).map_err(|err| {
                    error!(%err, "get initiator handshake data failed");

                    Error::Handshake(err)
                })?;

                Ok(&buffer[..n])
            }
            State::Transport(_) => {
                unreachable!("call initiator_handshake after initiator_handshake done");
            }
        }
    }

    pub fn initiator_handshake_response(&mut self, data: &[u8]) -> HandshakeState {
        match &mut self.state {
            State::Handshake(handshake, buffer) => match handshake.read_message(data, buffer) {
                Err(snow::Error::Input) => {
                    error!("invalid input");

                    HandshakeState::MissPeerPublicKey
                }

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

                        Some(public_key) => HandshakeState::PeerPublicKey(public_key),
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
            State::Handshake(handshake, buffer) => match handshake.read_message(data, buffer) {
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

                        Some(public_key) => HandshakeState::PeerPublicKey(public_key),
                    }
                }
            },

            State::Transport(_) => {
                unreachable!("call responder_handshake after responder_handshake done");
            }
        }
    }

    // #[instrument(err)]
    pub fn responder_handshake_response(&mut self) -> Result<&[u8], Error> {
        match &mut self.state {
            State::Handshake(state, buffer) => {
                let n = state.write_message(&[], buffer).map_err(|err| {
                    error!(%err, "get responder handshake response data failed");

                    Error::Handshake(err)
                })?;

                Ok(&buffer[..n])
            }
            State::Transport(_) => {
                unreachable!("call handshake_response after handshake done");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let builder = Builder::new(NOISE_PARAMS.clone());
        let initiator_keypair = builder.generate_keypair().unwrap();
        let responder_keypair = builder.generate_keypair().unwrap();

        let mut initiator_encrypt = Encrypt::new_initiator(&initiator_keypair.private).unwrap();
        let mut responder_encrypt = Encrypt::new_responder(&responder_keypair.private).unwrap();

        let initiator_handshake = initiator_encrypt.initiator_handshake().unwrap();
        let handshake_state = responder_encrypt.responder_handshake(initiator_handshake);
        match handshake_state {
            HandshakeState::PeerPublicKey(public_key) => {
                assert_eq!(public_key, initiator_keypair.public);
            }

            state => panic!("wrong state {state:?}"),
        }

        let responder_handshake = responder_encrypt.responder_handshake_response().unwrap();
        let handshake_state = initiator_encrypt.initiator_handshake_response(responder_handshake);
        match handshake_state {
            HandshakeState::PeerPublicKey(public_key) => {
                assert_eq!(public_key, responder_keypair.public);
            }

            state => panic!("wrong state {state:?}"),
        }
    }

    #[test]
    fn transport() {
        let builder = Builder::new(NOISE_PARAMS.clone());
        let initiator_keypair = builder.generate_keypair().unwrap();
        let responder_keypair = builder.generate_keypair().unwrap();

        let mut initiator_encrypt = Encrypt::new_initiator(&initiator_keypair.private).unwrap();
        let mut responder_encrypt = Encrypt::new_responder(&responder_keypair.private).unwrap();

        let initiator_handshake = initiator_encrypt.initiator_handshake().unwrap();
        let handshake_state = responder_encrypt.responder_handshake(initiator_handshake);
        assert!(matches!(handshake_state, HandshakeState::PeerPublicKey(_)));

        let responder_handshake = responder_encrypt.responder_handshake_response().unwrap();
        let handshake_state = initiator_encrypt.initiator_handshake_response(responder_handshake);
        assert!(matches!(handshake_state, HandshakeState::PeerPublicKey(_)));

        let initiator_encrypt = initiator_encrypt.into_transport_mode().unwrap();
        let responder_encrypt = responder_encrypt.into_transport_mode().unwrap();

        let mut initiator_buf = vec![0; 4096];
        let n = initiator_encrypt
            .encrypt(0, b"hello", &mut initiator_buf)
            .unwrap();

        let mut responder_buf = vec![0; 4096];
        let n = responder_encrypt
            .decrypt(0, &initiator_buf[..n], &mut responder_buf)
            .unwrap();

        assert_eq!(&responder_buf[..n], b"hello");

        let n = responder_encrypt
            .encrypt(1, b"world", &mut responder_buf)
            .unwrap();

        let n = initiator_encrypt
            .decrypt(1, &responder_buf[..n], &mut initiator_buf)
            .unwrap();

        assert_eq!(&initiator_buf[..n], b"world");
    }
}
