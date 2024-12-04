use anyhow::Context;
use std::path::Path;
use std::str::FromStr;

use ethers::signers::Wallet;
use k256::ecdsa::SigningKey;

pub enum WalletBackend {
    PrivateKey(redact::Secret<String>),
    Keystore {
        keystore_path: String,
        pwd: redact::Secret<String>,
    },
}

impl WalletBackend {
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
