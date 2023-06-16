use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use totp_rs::{Algorithm, TOTP};
use tracing::{error, instrument};

#[derive(Debug)]
pub struct AuthStore {
    auths: HashMap<String, Auth>,
}

impl AuthStore {
    pub fn new<I: IntoIterator<Item = (String, String)>>(auths: I) -> anyhow::Result<Self> {
        let auths = auths
            .into_iter()
            .map(|(public_id, token_secret)| {
                let auth = Auth::new(token_secret, None)?;

                Ok((public_id, auth))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?;

        Ok(Self { auths })
    }

    #[instrument]
    pub fn auth(&self, public_id: &str, hmac: &str) -> bool {
        match self.auths.get(public_id) {
            None => {
                error!("public id not found");

                false
            }

            Some(auth) => auth.auth(hmac),
        }
    }
}

pub struct Auth {
    totp: TOTP,
}

impl Debug for Auth {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth").finish_non_exhaustive()
    }
}

impl Auth {
    pub fn new(
        secret: String,
        account_name: impl Into<Option<String>>,
    ) -> Result<Self, totp_rs::TotpUrlError> {
        Ok(Self {
            totp: TOTP::new(
                Algorithm::SHA512,
                8,
                1,
                30,
                secret.into_bytes(),
                None,
                account_name
                    .into()
                    .unwrap_or_else(|| "default_account".to_string()),
            )?,
        })
    }

    fn auth(&self, token: &str) -> bool {
        self.totp.check_current(token).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use totp_rs::Algorithm;

    use super::*;

    #[test]
    fn check_auth() {
        let auth_store = AuthStore::new([(
            "public-id".to_string(),
            "test-secrettest-secret".to_string(),
        )])
        .unwrap();
        let totp = TOTP::new(
            Algorithm::SHA512,
            8,
            1,
            30,
            "test-secrettest-secret".to_string().into_bytes(),
            None,
            "default_account".to_string(),
        )
        .unwrap();

        let token = totp.generate_current().unwrap();
        dbg!(&token);

        assert!(auth_store.auth("public-id", &token));
    }
}
