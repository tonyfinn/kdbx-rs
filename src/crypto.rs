use crate::binary;

use aes::Aes256;
use cipher::generic_array::GenericArray;
use cipher::BlockEncryptMut;
use hmac::digest::CtOutput;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::string::ToString;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Credentials needed to unlock the database
///
/// Currently it supports unlocking a database with a combination
/// of password, keyfile or both.
///
/// For the compmon case of creating credentials from just a password,
/// you can use
///
/// ```
/// # use kdbx_rs::CompositeKey;
/// CompositeKey::from_password("abcdef");
/// ```
///
/// Otherwise you can use [`CompositeKey::new`] to provide other combinations
pub struct CompositeKey {
    pw: Option<String>,
    keyfile: Option<Vec<u8>>,
}

impl CompositeKey {
    /// Create a new composite key
    pub fn new(pw: Option<String>, keyfile: Option<Vec<u8>>) -> CompositeKey {
        CompositeKey { pw, keyfile }
    }

    /// Utility method for making a key with just a password
    pub fn from_password(pw: &str) -> CompositeKey {
        CompositeKey::new(Some(pw.into()), None)
    }

    pub(crate) fn composed(&self) -> ComposedKey {
        let mut buffer = Vec::new();
        if let Some(ref pw) = self.pw {
            buffer.extend(Sha256::digest(pw.as_bytes()))
            //buffer.extend(pw.as_bytes());
        }
        if let Some(ref keyfile) = self.keyfile {
            buffer.extend(Sha256::digest(keyfile))
        }

        ComposedKey(Sha256::digest(&buffer).iter().cloned().collect())
    }
}

#[derive(Debug)]
/// Hashed combined input credentials used as KDF input
pub struct ComposedKey(Vec<u8>);

impl ComposedKey {
    /// Generate a master key used to derive all other keys
    pub fn master_key(
        &self,
        kdf_options: &binary::KdfParams,
    ) -> Result<MasterKey, KeyGenerationError> {
        match kdf_options {
            binary::KdfParams::Argon2 {
                variant,
                memory_bytes,
                version,
                iterations,
                lanes,
                salt,
            } => {
                let config = argon2::Config {
                    variant: *variant,
                    version: argon2::Version::from_u32(*version)
                        .map_err(|e| KeyGenerationError::KeyGeneration(e.to_string()))?,
                    lanes: *lanes,
                    mem_cost: (memory_bytes / 1024) as u32,
                    time_cost: *iterations as u32,
                    ..Default::default()
                };
                let hash = argon2::hash_raw(&self.0, salt, &config)
                    .map_err(|e| KeyGenerationError::KeyGeneration(e.to_string()))?;

                Ok(MasterKey(hash))
            }
            binary::KdfParams::Aes { rounds, salt } => {
                use cipher::KeyInit;
                let mut cipher = Aes256::new_from_slice(salt).unwrap();
                let chunked: Vec<GenericArray<u8, _>> = self
                    .0
                    .chunks_exact(16)
                    .map(|chunk| *GenericArray::from_slice(chunk))
                    .collect();
                let mut blocks = [chunked[0], chunked[1]];
                for _ in 0..*rounds {
                    cipher.encrypt_blocks_mut(&mut blocks);
                }
                let mut transformed_hasher = Sha256::new();
                transformed_hasher.update(blocks[0]);
                transformed_hasher.update(blocks[1]);
                let transformed = transformed_hasher.finalize().to_vec();

                Ok(MasterKey(transformed))
            }
            _ => Ok(MasterKey(Vec::new())),
        }
    }
}

/// Master key - this is generated from the user's composite key and is used to generate all other keys
#[derive(Debug)]
pub struct MasterKey(Vec<u8>);

impl MasterKey {
    /// Obtain a key to use for data integrity checks
    pub(crate) fn hmac_key(&self, seed: &[u8]) -> HmacKey {
        let mut data_to_hash = Vec::new();
        data_to_hash.extend(seed.iter());
        data_to_hash.extend(self.0.iter());
        data_to_hash.push(1);

        HmacKey(Sha512::digest(&data_to_hash).iter().cloned().collect())
    }

    /// Obtain a key to initialise a cipher
    pub(crate) fn cipher_key(&self, seed: &[u8]) -> CipherKey {
        let mut data_to_hash = Vec::new();
        data_to_hash.extend(seed.iter());
        data_to_hash.extend(self.0.iter());

        CipherKey(Sha256::digest(&data_to_hash).iter().cloned().collect())
    }
}

/// Used to initialise the encryption/decryption cipher
pub(crate) struct CipherKey(pub(crate) Vec<u8>);

/// Base key for all HMAC data integrity checks
pub(crate) struct HmacKey(Vec<u8>);

impl HmacKey {
    /// Obtain a key to verify a single block
    pub(crate) fn block_key(&self, block_idx: u64) -> HmacBlockKey {
        let mut block_key_hash = Sha512::new();
        block_key_hash.update(block_idx.to_le_bytes());
        block_key_hash.update(&*self.0);
        HmacBlockKey(block_idx, block_key_hash.finalize().to_vec())
    }
}

/// Key to perform data integrity checks on a specific block
pub(crate) struct HmacBlockKey(u64, Vec<u8>);

impl HmacBlockKey {
    /// Verify that a block in the data section is valid
    pub(crate) fn verify_data_block(&self, hmac: &[u8], data: &[u8]) -> bool {
        let mut calc_hmac = HmacSha256::new_from_slice(&self.1).unwrap();
        calc_hmac.update(&self.0.to_le_bytes());
        calc_hmac.update(&(data.len() as u32).to_le_bytes());
        calc_hmac.update(data);
        calc_hmac.verify_slice(hmac).is_ok()
    }

    /// Calculate a HMAC for a block in the data section
    pub(crate) fn calculate_data_hmac(
        &self,
        data: &[u8],
    ) -> Result<CtOutput<HmacSha256>, cipher::InvalidLength> {
        let mut calc_hmac: HmacSha256 = HmacSha256::new_from_slice(&self.1).unwrap();
        calc_hmac.update(&self.0.to_le_bytes());
        calc_hmac.update(&(data.len() as u32).to_le_bytes());
        calc_hmac.update(data);
        Ok(calc_hmac.finalize())
    }

    /// Calculate a HMAC for a block in the header section
    pub(crate) fn calculate_header_hmac(
        &self,
        data: &[u8],
    ) -> Result<CtOutput<HmacSha256>, cipher::InvalidLength> {
        let mut calc_hmac = HmacSha256::new_from_slice(&self.1)?;
        calc_hmac.update(data);
        Ok(calc_hmac.finalize())
    }

    /// Verify that the header block is valid
    pub(crate) fn verify_header_block(&self, hmac: &[u8], data: &[u8]) -> bool {
        let mut calc_hmac = HmacSha256::new_from_slice(&self.1).unwrap();
        calc_hmac.update(data);
        calc_hmac.verify_slice(hmac).is_ok()
    }
}

/// Confirm the hash of a given block of data for data corruption detection
pub(crate) fn verify_sha256(data: &[u8], expected_sha: &[u8]) -> bool {
    expected_sha == &*Sha256::digest(data)
}

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).as_slice().to_vec()
}

#[derive(Debug, Error)]
/// Errors encountered generating crypto keys
pub enum KeyGenerationError {
    /// Unexpected error when generating a key
    #[error("Could not generate key: {0}")]
    KeyGeneration(String),
    /// KDF Options are not supported by this library
    #[error("Generation for KDF Options: {0:?} not implemented")]
    UnimplementedKdfOptions(binary::KdfParams),
}
