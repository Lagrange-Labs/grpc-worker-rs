use anyhow::{bail, Context};
use redact::Secret;
use std::path::Path;
use std::str::FromStr;

use ethers::signers::Wallet;
use k256::ecdsa::SigningKey;

/// Different ways to instantiate a wallet necessary to perform the JWT auth with the Gateway.
pub enum WalletBackend {
    PrivateKey(redact::Secret<String>),
    Keystore {
        keystore_path: String,
        pwd: redact::Secret<String>,
    },
}

impl WalletBackend {
    pub fn from_triplet(
        keystore_path: Option<String>,
        keystore_pwd: Option<Secret<String>>,
        private_key: Option<Secret<String>>,
    ) -> anyhow::Result<Self> {
        match (keystore_path, keystore_pwd, private_key) {
            (Some(keystore_path), Some(password), None) => Ok(WalletBackend::Keystore {
                keystore_path: keystore_path.clone(),
                pwd: password.clone(),
            }),
            (Some(_), None, Some(pkey)) => Ok(WalletBackend::PrivateKey(pkey.clone())),
            _ => bail!("Must specify either keystore path w/ password OR private key"),
        }
    }
    pub fn get_wallet(&self) -> anyhow::Result<Wallet<SigningKey>> {
        match self {
            WalletBackend::PrivateKey(key) => Wallet::from_str(key.expose_secret())
                .context("Failed to create wallet from private key"),
            WalletBackend::Keystore { keystore_path, pwd } => {
                read_keystore(keystore_path, pwd.expose_secret()).context("failed to read keystore")
            }
        }
    }
}

/// Read the key-store from a file path with the sepcified password.
fn read_keystore<P: AsRef<Path>, S: AsRef<[u8]>>(
    key_path: P,
    password: S,
) -> anyhow::Result<Wallet<SigningKey>> {
    let wallet = Wallet::<SigningKey>::decrypt_keystore(&key_path, password)
        .with_context(|| format!("while trying to open `{}`", key_path.as_ref().display()))?;

    Ok(wallet)
}
