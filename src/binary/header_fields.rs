use super::errors::HeaderError;
use super::header::{HeaderField, InnerHeaderId, OuterHeaderId};
use super::variant_dict::{self, VariantDict};
use crate::utils;
use std::convert::{TryFrom, TryInto};
use uuid::Uuid;

pub const KEEPASS_MAGIC_NUMBER: u32 = 0x9AA2_D903;
pub const KDBX_MAGIC_NUMBER: u32 = 0xB54B_FB67;

const AES128_UUID: &str = "61ab05a1-9464-41c3-8d74-3a563df8dd35";
const AES256_UUID: &str = "31c1f2e6-bf71-4350-be58-05216afc5aff";
const TWOFISH_UUID: &str = "ad68f29f-576f-4bb9-a36a-d47af965346c";
const CHACHA20_UUID: &str = "d6038a2b-8b6f-4cb5-a524-339a31dbb59a";
const AES_3_1_UUID: &str = "c9d9f39a-628a-4460-bf74-0d08c18a4fea";
const AES_4_UUID: &str = "7c02bb82-79a7-4ac0-927d-114a00648238";
const ARGON2D_UUID: &str = "ef636ddf-8c29-444b-91f7-a9a403e30a0c";
const ARGON2ID_UUID: &str = "9e298b19-56db-4773-b23d-fc3ec6f0a1e6";
const COMPRESSION_TYPE_NONE: u32 = 0;
const COMPRESSION_TYPE_GZIP: u32 = 1;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
/// Encryption cipher used for decryption the main database data
pub enum Cipher {
    /// AES 128 in CBC mode
    Aes128,
    /// AES 256 in CBC mode
    Aes256,
    /// TwoFish in CBC mode
    TwoFish,
    /// ChaCha20 in streaming mode
    ChaCha20,
    /// Cipher unknown to this library
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
        utils::value_from_uuid_table(&CIPHER_TABLE, uuid).unwrap_or(Cipher::Unknown(uuid))
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

impl From<Cipher> for HeaderField<OuterHeaderId> {
    fn from(cipher: Cipher) -> HeaderField<OuterHeaderId> {
        let uuid: uuid::Uuid = cipher.into();
        HeaderField::new(OuterHeaderId::CipherId, uuid.as_bytes().to_vec())
    }
}

/// Inner stream cipher identifier used for encrypting protected fields
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum InnerStreamCipherAlgorithm {
    /// ArcFour algorithm
    ArcFour,
    /// Salsa20 stream cipher
    Salsa20,
    /// ChaCha20 stream cipher
    ChaCha20,
    /// Unknown stream cipher
    Unknown(u32),
}

impl From<InnerStreamCipherAlgorithm> for HeaderField<InnerHeaderId> {
    fn from(cipher: InnerStreamCipherAlgorithm) -> HeaderField<InnerHeaderId> {
        HeaderField::new(
            InnerHeaderId::InnerRandomStreamCipherId,
            u32::from(cipher).to_le_bytes().as_ref().to_vec(),
        )
    }
}

impl From<u32> for InnerStreamCipherAlgorithm {
    fn from(id: u32) -> InnerStreamCipherAlgorithm {
        match id {
            1 => InnerStreamCipherAlgorithm::ArcFour,
            2 => InnerStreamCipherAlgorithm::Salsa20,
            3 => InnerStreamCipherAlgorithm::ChaCha20,
            x => InnerStreamCipherAlgorithm::Unknown(x),
        }
    }
}

impl From<InnerStreamCipherAlgorithm> for u32 {
    fn from(id: InnerStreamCipherAlgorithm) -> u32 {
        match id {
            InnerStreamCipherAlgorithm::ArcFour => 1,
            InnerStreamCipherAlgorithm::Salsa20 => 2,
            InnerStreamCipherAlgorithm::ChaCha20 => 3,
            InnerStreamCipherAlgorithm::Unknown(x) => x,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
/// Algorithm used for converting from credentials to crypto keys
pub enum KdfAlgorithm {
    /// Argon2d KDF
    Argon2d,
    /// Argon2id KDF
    Argon2id,
    /// AES 256 as used in KDBX4+
    Aes256_Kdbx4,
    /// AES 256 as used in KDBX3.1
    Aes256_Kdbx3_1,
    /// Unknown key derivation function
    Unknown(uuid::Uuid),
}

pub(crate) const KDF_TABLE: [(&str, KdfAlgorithm); 4] = [
    (AES_3_1_UUID, KdfAlgorithm::Aes256_Kdbx3_1),
    (AES_4_UUID, KdfAlgorithm::Aes256_Kdbx4),
    (ARGON2D_UUID, KdfAlgorithm::Argon2d),
    (ARGON2ID_UUID, KdfAlgorithm::Argon2id),
];

impl From<uuid::Uuid> for KdfAlgorithm {
    fn from(uuid: uuid::Uuid) -> KdfAlgorithm {
        utils::value_from_uuid_table(&KDF_TABLE, uuid).unwrap_or(KdfAlgorithm::Unknown(uuid))
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Options for converting credentials to crypto keys
pub enum KdfParams {
    /// Argon 2 KDF
    Argon2 {
        /// Argon2 variant
        variant: argon2::Variant,
        /// Amount of memory to use for key gen
        memory_bytes: u64,
        /// Argon2 version used (this library supports v19/0x13)
        version: u32,
        /// Random seed data to use for the KDF
        salt: Vec<u8>,
        /// Number of parallel tasks to use
        lanes: u32,
        /// Passes of the KDF to use for key gen
        iterations: u64,
    },
    /// AES256 KDF
    Aes {
        /// Rounds of AES to use for key generation
        rounds: u64,
        /// Random seed data to use for the KDF
        salt: Vec<u8>,
    },
    /// Some KDF unknown to this library
    Unknown {
        /// UUID to identify the KDF used
        uuid: uuid::Uuid,
        /// Parameters to the KDF
        params: variant_dict::VariantDict,
    },
}

impl TryFrom<VariantDict> for KdfParams {
    type Error = HeaderError;
    fn try_from(mut vdict: VariantDict) -> Result<Self, HeaderError> {
        let uuid_val = vdict.remove("$UUID").ok_or_else(|| {
            HeaderError::MalformedField(
                OuterHeaderId::KdfParameters,
                "No UUID for kdf parameters".into(),
            )
        })?;
        let uuid_array: Vec<u8> = uuid_val.try_into().map_err(|_| {
            HeaderError::MalformedField(
                OuterHeaderId::KdfParameters,
                "KDF UUID not a byte array".into(),
            )
        })?;
        let uuid = Uuid::from_slice(&uuid_array).map_err(|_| {
            HeaderError::MalformedField(
                OuterHeaderId::KdfParameters,
                "KDF UUID not a valid UUID".into(),
            )
        })?;

        let kdf_algorithm = KdfAlgorithm::from(uuid);

        match kdf_algorithm {
            KdfAlgorithm::Argon2d | KdfAlgorithm::Argon2id => {
                let memory_bytes =
                    KdfParams::opt_from_vdict("M", KdfAlgorithm::Argon2d, &mut vdict)?;
                let version = KdfParams::opt_from_vdict("V", KdfAlgorithm::Argon2d, &mut vdict)?;
                let salt = KdfParams::opt_from_vdict("S", KdfAlgorithm::Argon2d, &mut vdict)?;
                let iterations = KdfParams::opt_from_vdict("I", KdfAlgorithm::Argon2d, &mut vdict)?;
                let lanes = KdfParams::opt_from_vdict("P", KdfAlgorithm::Argon2d, &mut vdict)?;
                Ok(KdfParams::Argon2 {
                    variant: utils::argon2_algo_to_variant(kdf_algorithm),
                    memory_bytes,
                    version,
                    salt,
                    iterations,
                    lanes,
                })
            }
            KdfAlgorithm::Aes256_Kdbx3_1 | KdfAlgorithm::Aes256_Kdbx4 => {
                let rounds =
                    KdfParams::opt_from_vdict("R", KdfAlgorithm::Aes256_Kdbx4, &mut vdict)?;
                let salt = KdfParams::opt_from_vdict("S", KdfAlgorithm::Aes256_Kdbx4, &mut vdict)?;
                Ok(KdfParams::Aes { rounds, salt })
            }
            _ => Ok(KdfParams::Unknown {
                uuid,
                params: vdict,
            }),
        }
    }
}

impl From<KdfParams> for VariantDict {
    fn from(params: KdfParams) -> VariantDict {
        let mut vdict = variant_dict::VariantDict::new();
        match params {
            KdfParams::Argon2 {
                variant,
                memory_bytes,
                version,
                salt,
                lanes,
                iterations,
            } => {
                vdict.insert(
                    "$UUID".into(),
                    variant_dict::Value::Array(
                        uuid::Uuid::from(utils::argon2_variant_to_algo(variant))
                            .as_bytes()
                            .to_vec(),
                    ),
                );
                vdict.insert("M".into(), variant_dict::Value::Uint64(memory_bytes));
                vdict.insert("V".into(), variant_dict::Value::Uint32(version));
                vdict.insert("S".into(), variant_dict::Value::Array(salt));
                vdict.insert("I".into(), variant_dict::Value::Uint64(iterations));
                vdict.insert("P".into(), variant_dict::Value::Uint32(lanes));
            }
            KdfParams::Aes { rounds, salt } => {
                vdict.insert(
                    "$UUID".into(),
                    variant_dict::Value::Array(
                        uuid::Uuid::from(KdfAlgorithm::Aes256_Kdbx4)
                            .as_bytes()
                            .to_vec(),
                    ),
                );
                vdict.insert("R".into(), variant_dict::Value::Uint64(rounds));
                vdict.insert("S".into(), variant_dict::Value::Array(salt));
            }
            KdfParams::Unknown { uuid, params } => {
                vdict.insert(
                    "$UUID".into(),
                    variant_dict::Value::Array(uuid.as_bytes().to_vec()),
                );
                vdict.extend(params.into_iter())
            }
        }
        vdict
    }
}

impl From<KdfParams> for HeaderField<OuterHeaderId> {
    fn from(params: KdfParams) -> HeaderField<OuterHeaderId> {
        let mut buf = Vec::new();
        let vdict: VariantDict = params.into();
        variant_dict::write_variant_dict(&mut buf, &vdict).unwrap();
        HeaderField::new(OuterHeaderId::KdfParameters, buf)
    }
}

impl KdfParams {
    fn opt_from_vdict<T>(
        key: &str,
        algo: KdfAlgorithm,
        vdict: &mut variant_dict::VariantDict,
    ) -> Result<T, HeaderError>
    where
        T: TryFrom<variant_dict::Value>,
    {
        vdict
            .remove(key)
            .and_then(|val| val.try_into().ok())
            .ok_or_else(|| HeaderError::MissingKdfParam(key.to_string(), algo))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Compression method used prior to encryption
pub enum CompressionType {
    /// The encrypted data is uncompressed
    None,
    /// The encrypted data uses gzip compression
    Gzip,
    /// The crypted data uses a compression method unsupported by this library
    Unknown(u32),
}

impl From<CompressionType> for u32 {
    fn from(compression_type: CompressionType) -> u32 {
        match compression_type {
            CompressionType::None => COMPRESSION_TYPE_NONE,
            CompressionType::Gzip => COMPRESSION_TYPE_GZIP,
            CompressionType::Unknown(val) => val,
        }
    }
}

impl From<u32> for CompressionType {
    fn from(id: u32) -> CompressionType {
        match id {
            COMPRESSION_TYPE_NONE => CompressionType::None,
            COMPRESSION_TYPE_GZIP => CompressionType::Gzip,
            _ => CompressionType::Unknown(id),
        }
    }
}

impl From<CompressionType> for HeaderField<OuterHeaderId> {
    fn from(compression_type: CompressionType) -> HeaderField<OuterHeaderId> {
        let compression_type_id: u32 = compression_type.into();
        HeaderField::new(
            OuterHeaderId::CompressionFlags,
            Vec::from(compression_type_id.to_le_bytes().as_ref()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use uuid::Uuid;
    #[test]
    fn kdf_from_slice() {
        let aes31 = Uuid::parse_str(AES_3_1_UUID).unwrap();
        let aes4 = Uuid::parse_str(AES_4_UUID).unwrap();
        let argon2 = Uuid::parse_str(ARGON2D_UUID).unwrap();
        let invalid = Uuid::parse_str(AES128_UUID).unwrap();

        assert_eq!(KdfAlgorithm::from(aes31), KdfAlgorithm::Aes256_Kdbx3_1);
        assert_eq!(KdfAlgorithm::from(aes4), KdfAlgorithm::Aes256_Kdbx4);
        assert_eq!(KdfAlgorithm::from(argon2), KdfAlgorithm::Argon2d);
        assert_eq!(KdfAlgorithm::from(invalid), KdfAlgorithm::Unknown(invalid));
    }
}
