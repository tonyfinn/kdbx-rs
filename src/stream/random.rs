use chacha20::ChaCha20;
use cipher::KeyIvInit;
use cipher::StreamCipher;
use salsa20::Salsa20;
use sha2::{Digest, Sha256, Sha512};
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
    /// Create a stream cipher instance for this algorithm
    pub fn stream_cipher(self, key: &[u8]) -> Result<Box<dyn StreamCipher>, InnerStreamError> {
        match self {
            InnerStreamCipherAlgorithm::ChaCha20 => {
                let iv = Sha512::digest(key);
                Ok(Box::new(
                    ChaCha20::new_from_slices(&iv[0..32], &iv[32..44]).unwrap(),
                ))
            }
            InnerStreamCipherAlgorithm::Salsa20 => {
                let iv = Sha256::digest(key);
                Ok(Box::new(
                    Salsa20::new_from_slices(&iv[0..32], &SALSA20_IV).unwrap(),
                ))
            }
            _ => Err(InnerStreamError::UnsupportedCipher(self)),
        }
    }
}
