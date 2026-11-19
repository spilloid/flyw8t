use std::io::{Cursor, Read};

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{aead, agreement, rand::SystemRandom};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;

pub const MAX_PNG: usize = 512 * 1024;
const HEADER_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const MAX_PIXELS: u64 = 8 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Crop {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub session_id: Uuid,
    pub request_id: Uuid,
    pub crop: Option<Crop>,
}

impl Arguments {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.session_id.is_nil() && !self.request_id.is_nil(),
            "Select a support session and supply a nonempty request UUID."
        );
        if let Some(c) = &self.crop {
            ensure!(c.x >= 0.0 && c.y >= 0.0 && c.width > 0.0 && c.height > 0.0 && c.x + c.width <= 1.0 && c.y + c.height <= 1.0,
                "The crop must have positive area and fit inside the shared frame using coordinates from 0 to 1.");
        }
        Ok(())
    }

    fn aad(&self) -> String {
        format!(
            "flyw8t-screenshot-v1\n{}\n{}",
            self.session_id, self.request_id
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub public_key: String,
    pub iv: String,
    pub ciphertext: String,
}

pub struct RequestKey(agreement::EphemeralPrivateKey);

impl RequestKey {
    pub fn generate() -> Result<Self> {
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &SystemRandom::new())
            .map(Self)
            .map_err(|_| anyhow!("Could not generate a screenshot delivery key."))
    }

    pub fn public_key(&self) -> Result<String> {
        Ok(STANDARD.encode(
            self.0
                .compute_public_key()
                .map_err(|_| anyhow!("Could not prepare the screenshot delivery key."))?,
        ))
    }

    pub fn open(self, envelope: Envelope, args: &Arguments) -> Result<Frame> {
        let peer_key = STANDARD
            .decode(envelope.public_key)
            .context("Invalid screenshot sender key.")?;
        ensure!(
            peer_key.len() == 65 && peer_key[0] == 4,
            "Unexpected screenshot sender key."
        );
        let nonce = STANDARD
            .decode(envelope.iv)
            .context("Invalid screenshot nonce.")?;
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| anyhow!("Unexpected screenshot nonce."))?;
        let mut body = STANDARD
            .decode(envelope.ciphertext)
            .context("Invalid screenshot envelope.")?;
        ensure!(
            body.len() <= MAX_PNG + HEADER_SIZE + TAG_SIZE,
            "Screenshot exceeds the delivery limit."
        );
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_key);
        let key = agreement::agree_ephemeral(self.0, &peer, |key| {
            aead::UnboundKey::new(&aead::AES_256_GCM, key)
        })
        .map_err(|_| anyhow!("Invalid screenshot sender key."))?
        .map_err(|_| anyhow!("Invalid screenshot delivery key."))?;
        let clear = aead::LessSafeKey::new(key)
            .open_in_place(nonce, aead::Aad::from(args.aad().as_bytes()), &mut body)
            .map_err(|_| {
                anyhow!("The screenshot failed its session and request integrity check.")
            })?;
        Frame::parse(clear)
    }
}

pub struct Frame {
    pub observed_at_ms: u64,
    pub width: u32,
    pub height: u32,
    pub png: String,
}

impl Frame {
    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() > HEADER_SIZE && bytes.len() <= MAX_PNG + HEADER_SIZE,
            "Invalid screenshot size."
        );
        let (header, image) = bytes.split_at(HEADER_SIZE);
        let mut header = Cursor::new(header);
        let mut time = [0u8; 8];
        let mut width = [0u8; 4];
        let mut height = [0u8; 4];
        header.read_exact(&mut time)?;
        header.read_exact(&mut width)?;
        header.read_exact(&mut height)?;
        let (width, height) = (u32::from_be_bytes(width), u32::from_be_bytes(height));
        ensure!(
            width > 0
                && height > 0
                && width <= 8192
                && height <= 8192
                && u64::from(width) * u64::from(height) <= MAX_PIXELS,
            "Screenshot dimensions exceed the supported range."
        );

        // A browser canvas emits a single PNG. Bound expansion before returning data to a client decoder.
        let mut decoder = png::Decoder::new(Cursor::new(image));
        decoder.set_limits(png::Limits {
            bytes: 40 * 1024 * 1024,
        });
        decoder.set_ignore_text_chunk(true);
        decoder.set_ignore_iccp_chunk(true);
        let mut reader = decoder
            .read_info()
            .map_err(|_| anyhow!("Invalid screenshot PNG header."))?;
        let info = reader.info();
        ensure!(
            info.width == width && info.height == height && info.animation_control.is_none(),
            "Screenshot dimensions or frame count do not match the envelope."
        );
        let output = reader
            .output_buffer_size()
            .filter(|&n| n <= 40 * 1024 * 1024)
            .context("Screenshot expands beyond the image limit.")?;
        let mut decoded = vec![0; output];
        reader
            .next_frame(&mut decoded)
            .map_err(|_| anyhow!("The screenshot PNG is incomplete."))?;
        reader
            .finish()
            .map_err(|_| anyhow!("The screenshot PNG is incomplete."))?;
        if !image.ends_with(&[0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130]) {
            bail!("Unexpected data following the screenshot PNG.");
        }
        Ok(Self {
            observed_at_ms: u64::from_be_bytes(time),
            width,
            height,
            png: STANDARD.encode(image),
        })
    }
}
