use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use totp_rs::{Algorithm, TOTP};

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

    pub fn auth(&self, public_id: &str, hmac: &str) -> bool {
        self.auths
            .get(public_id)
            .map(|auth| auth.auth(hmac))
            .unwrap_or(false)
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
        let secret = "test-secrettest-secret".to_string();
        let account_name = "test".to_string();

        let totp = TOTP::new(
            Algorithm::SHA512,
            8,
            1,
            30,
            secret.clone().into_bytes(),
            None,
            account_name.clone(),
        )
        .unwrap();

        let auth = Auth::new(secret, account_name).unwrap();

        let token = totp.generate_current().unwrap();

        dbg!(&token);

        assert!(auth.auth(&token));
    }

    #[test]
    fn check_auth_with_different_account_name() {
        let secret = "test-secrettest-secret".to_string();

        let totp = TOTP::new(
            Algorithm::SHA512,
            8,
            1,
            30,
            secret.clone().into_bytes(),
            None,
            "test".to_string(),
        )
        .unwrap();

        let auth = Auth::new(secret, None).unwrap();

        let token = totp.generate_current().unwrap();

        dbg!(&token);

        assert!(auth.auth(&token));
    }
}
