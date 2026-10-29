//! The device's Ed25519 identity key.
//!
//! Generated on the device at enrollment; only the public half is sent to the server. Every
//! connection is authenticated by signing the server's fresh nonce with it.

use anyhow::{Context, Result};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;

pub struct DeviceKey {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
}

impl DeviceKey {
    pub fn generate() -> Result<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("generating device key"))?;
        Self::from_pkcs8(pkcs8.as_ref().to_vec())
    }

    fn from_pkcs8(pkcs8: Vec<u8>) -> Result<Self> {
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| anyhow::anyhow!("device key is corrupt"))?;
        Ok(Self { pair, pkcs8 })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let pkcs8 = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_pkcs8(pkcs8)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::config::write_atomic(path, &self.pkcs8)
    }

    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.pair.public_key().as_ref())
    }

    pub fn public_key(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }

    pub fn sign_b64(&self, message: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.pair.sign(message).as_ref())
    }
}
