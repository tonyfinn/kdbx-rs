use chacha20::ChaCha20;
use rand::{rngs::OsRng, RngCore};
use salsa20::Salsa20;
use sha2::{Digest, Sha256, Sha512};
use stream_cipher::{NewStreamCipher, StreamCipher};
use thiserror::Error;

use crate::binary::InnerStreamCipherAlgorithm;

pub const SALSA20_IV: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

#[derive(Debug, Error)]
/// Errors creating inner stream used to decrypt protected values
pub enum InnerStreamError {
    #[error("Unsupported inner stream type: {0:?}")]
    /// The cipher type is not supported by this library
    UnsupportedCipher(InnerStreamCipherAlgorithm),
}

impl InnerStreamCipherAlgorithm {
    pub(crate) fn stream_cipher(
        self,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, InnerStreamError> {
        match self {
            InnerStreamCipherAlgorithm::ChaCha20 => {
                let iv = Sha512::digest(key);
                Ok(Box::new(
                    ChaCha20::new_var(&iv[0..32], &iv[32..44]).unwrap(),
                ))
            }
            InnerStreamCipherAlgorithm::Salsa20 => {
                let iv = Sha256::digest(key);
                Ok(Box::new(Salsa20::new_var(&iv[0..32], &SALSA20_IV).unwrap()))
            }
            _ => Err(InnerStreamError::UnsupportedCipher(self)),
        }
    }
}

/// Return a default stream cipher and its key
///
/// The stream cipher is created using ChaCha20, and the key is generated from OS randomness.
pub fn default_stream_cipher() -> (impl StreamCipher, Vec<u8>) {
    let mut key = vec![0u8; 64];
    OsRng.fill_bytes(&mut key);
    let iv = Sha256::digest(key.as_ref());
    let cipher = ChaCha20::new_var(&iv[0..32], &iv[32..44]).unwrap();

    (cipher, key)
}
