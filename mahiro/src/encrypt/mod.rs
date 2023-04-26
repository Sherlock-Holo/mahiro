use std::str::FromStr;

use once_cell::sync::Lazy;
use snow::params::NoiseParams;

static NOISE_PARAMS: Lazy<NoiseParams> =
    Lazy::new(|| NoiseParams::from_str("Noise_IX_25519_ChaChaPoly_BLAKE2s").unwrap());
