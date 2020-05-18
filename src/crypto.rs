use crate::utils;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::string::ToString;
use thiserror::Error;

pub const AES128_UUID: &str = "61ab05a1-9464-41c3-8d74-3a563df8dd35";
pub const AES256_UUID: &str = "31c1f2e6-bf71-4350-be58-05216afc5aff";
pub const TWOFISH_UUID: &str = "ad68f29f-576f-4bb9-a36a-d47af965346c";
pub const CHACHA20_UUID: &str = "d6038a2b-8b6f-4cb5-a524-339a31dbb59a";
pub const AES_3_1_UUID: &str = "c9d9f39a-628a-4460-bf74-0d08c18a4fea";
pub const AES_4_UUID: &str = "7c02bb82-79a7-4ac0-927d-114a00648238";
pub const ARGON2_UUID: &str = "ef636ddf-8c29-444b-91f7-a9a403e30a0c";

type HmacSha256 = Hmac<Sha256>;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum Cipher {
    Aes128,
    Aes256,
    TwoFish,
    ChaCha20,
    Unknown(uuid::Uuid),
}

const CIPHER_TABLE: [(&str, Cipher); 4] = [
    (AES128_UUID, Cipher::Aes128),
    (AES256_UUID, Cipher::Aes256),
    (TWOFISH_UUID, Cipher::TwoFish),
    (CHACHA20_UUID, Cipher::ChaCha20),
];

impl From<uuid::Uuid> for Cipher {
    fn from(uuid: uuid::Uuid) -> Cipher {
        utils::value_from_uuid_table(&CIPHER_TABLE, uuid).unwrap_or_else(|| Cipher::Unknown(uuid))
    }
}

impl From<Cipher> for uuid::Uuid {
    fn from(cipher: Cipher) -> uuid::Uuid {
        match cipher {
            Cipher::Unknown(uuid) => uuid,
            _ => utils::uuid_from_uuid_table(&CIPHER_TABLE, cipher).unwrap(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum KdfAlgorithm {
    Argon2,
    Aes256_Kdbx4,
    Aes256_Kdbx3_1,
    Unknown(uuid::Uuid),
}

pub(crate) const KDF_TABLE: [(&str, KdfAlgorithm); 3] = [
    (AES_3_1_UUID, KdfAlgorithm::Aes256_Kdbx3_1),
    (AES_4_UUID, KdfAlgorithm::Aes256_Kdbx4),
    (ARGON2_UUID, KdfAlgorithm::Argon2),
];

impl From<uuid::Uuid> for KdfAlgorithm {
    fn from(uuid: uuid::Uuid) -> KdfAlgorithm {
        utils::value_from_uuid_table(&KDF_TABLE, uuid)
            .unwrap_or_else(|| KdfAlgorithm::Unknown(uuid))
    }
}

impl From<KdfAlgorithm> for uuid::Uuid {
    fn from(algo: KdfAlgorithm) -> uuid::Uuid {
        match algo {
            KdfAlgorithm::Unknown(uuid) => uuid,
            _ => utils::uuid_from_uuid_table(&KDF_TABLE, algo).unwrap(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KdfOptions {
    Argon2 {
        memory_bytes: u64,
        version: u32,
        salt: Vec<u8>,
        lanes: u32,
        // aka passes, aka It
        iterations: u64,
    },
    Aes {
        rounds: u64,
        salt: Vec<u8>,
    },
    Other {
        uuid: uuid::Uuid,
        params: crate::variant_dict::VariantDict,
    },
}

/// Credentials needed to unlock the database
pub struct CompositeKey {
    pw: Option<String>,
    keyfile: Option<Vec<u8>>,
}

impl CompositeKey {
    /// Utility method for making a key with just a password
    pub fn pwonly(pw: &str) -> CompositeKey {
        CompositeKey {
            pw: Some(pw.into()),
            keyfile: None,
        }
    }

    fn composed(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        if let Some(ref pw) = self.pw {
            buffer.extend(Sha256::digest(pw.as_bytes()))
            //buffer.extend(pw.as_bytes());
        }
        if let Some(ref keyfile) = self.keyfile {
            buffer.extend(Sha256::digest(keyfile))
        }

        Sha256::digest(&buffer).iter().cloned().collect()
    }

    /// Generate a master key used to derive all other keys
    pub(crate) fn master_key(
        &self,
        kdf_options: &KdfOptions,
    ) -> Result<MasterKey, KeyGenerationError> {
        match kdf_options {
            KdfOptions::Argon2 {
                memory_bytes,
                version,
                iterations,
                lanes,
                salt,
            } => {
                let config = argon2::Config {
                    variant: argon2::Variant::Argon2d,
                    version: argon2::Version::from_u32(*version)
                        .map_err(|e| KeyGenerationError::KeyGeneration(e.to_string()))?,
                    lanes: *lanes,
                    mem_cost: (memory_bytes / 1024) as u32,
                    thread_mode: argon2::ThreadMode::Parallel,
                    time_cost: *iterations as u32,
                    ..Default::default()
                };
                let hash = argon2::hash_raw(&self.composed(), salt, &config)
                    .map_err(|e| KeyGenerationError::KeyGeneration(e.to_string()))?;

                Ok(MasterKey(hash))
            }
            _ => Ok(MasterKey(Vec::new())),
        }
    }
}

/// Master key - this is generated from the user's composite key and is used to generate all other keys
pub(crate) struct MasterKey(Vec<u8>);

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
        block_key_hash.input(&block_idx.to_le_bytes());
        block_key_hash.input(&*self.0);
        HmacBlockKey(block_idx, block_key_hash.result().iter().cloned().collect())
    }
}

/// Key to perform data integrity checks on a specific block
pub(crate) struct HmacBlockKey(u64, Vec<u8>);

impl HmacBlockKey {
    /// Verify that a block in the data section is valid
    pub(crate) fn verify_data_block(&self, hmac: &[u8], data: &[u8]) -> bool {
        let mut calc_hmac = HmacSha256::new_varkey(&self.1).unwrap();
        calc_hmac.input(&self.0.to_le_bytes());
        calc_hmac.input(&(data.len() as u32).to_le_bytes());
        calc_hmac.input(data);
        match calc_hmac.verify(hmac) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Verify that the header block is valid
    pub(crate) fn verify_header_block(&self, hmac: &[u8], data: &[u8]) -> bool {
        let mut calc_hmac = HmacSha256::new_varkey(&self.1).unwrap();
        calc_hmac.input(data);
        match calc_hmac.verify(hmac) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// Confirm the hash of a given block of data for data corruption detection
pub(crate) fn verify_sha256(data: &[u8], expected_sha: &[u8]) -> bool {
    expected_sha == &*Sha256::digest(&data)
}

#[derive(Debug, Error)]
pub enum KeyGenerationError {
    #[error("Could not generate key: {0}")]
    KeyGeneration(String),
    #[error("Generation for KDF Options: {0:?} not implemented")]
    UnimplementedKdfOptions(KdfOptions),
}

#[cfg(test)]
mod tests {
    use super::*;

    use uuid::Uuid;
    #[test]
    fn kdf_from_slice() {
        let aes31 = Uuid::parse_str(AES_3_1_UUID).unwrap();
        let aes4 = Uuid::parse_str(AES_4_UUID).unwrap();
        let argon2 = Uuid::parse_str(ARGON2_UUID).unwrap();
        let invalid = Uuid::parse_str(AES128_UUID).unwrap();

        assert_eq!(KdfAlgorithm::from(aes31), KdfAlgorithm::Aes256_Kdbx3_1);
        assert_eq!(KdfAlgorithm::from(aes4), KdfAlgorithm::Aes256_Kdbx4);
        assert_eq!(KdfAlgorithm::from(argon2), KdfAlgorithm::Argon2);
        assert_eq!(
            KdfAlgorithm::from(invalid.clone()),
            KdfAlgorithm::Unknown(invalid.clone())
        );
    }
}
