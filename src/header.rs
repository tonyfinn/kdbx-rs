use crate::crypto;
use crate::utils;
use crate::variant_dict;
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use std::io::Read;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error reading database header - {0}")]
    Io(#[from] std::io::Error),
    #[error("Incompatible database - Malformed field of type {0:?}")]
    MalformedField(HeaderType),
    #[error("Incompatible database - Missing required field of type {0:?}")]
    MissingRequiredField(HeaderType),
    #[error("Incompatible database - Missing paramater {0:?} for KDF {1:?}")]
    MissingKdfParam(String, crypto::KdfAlgorithm),
    #[error("Corrupt database - Header Checksum failed")]
    ChecksumFailed,
    #[error("Incompatible database - Unknown cipher {0:?}")]
    UnknownCipher(uuid::Uuid),
}

type Result<T> = std::result::Result<T, Error>;

impl TryFrom<variant_dict::VariantDict> for crypto::KdfOptions {
    type Error = Error;
    fn try_from(mut vdict: variant_dict::VariantDict) -> Result<Self> {
        let uuid = vdict
            .remove("$UUID")
            .and_then(|uuid_val| uuid_val.try_into().ok())
            .and_then(|array: Vec<u8>| Uuid::from_slice(&array).ok())
            .ok_or_else(|| Error::MalformedField(HeaderType::KdfParameters))?;

        let kdf_algorithm = crypto::KdfAlgorithm::from(uuid.clone());

        match kdf_algorithm {
            crypto::KdfAlgorithm::Argon2 => {
                let memory_bytes = crypto::KdfOptions::opt_from_vdict(
                    "M",
                    crypto::KdfAlgorithm::Argon2,
                    &mut vdict,
                )?;
                let version = crypto::KdfOptions::opt_from_vdict(
                    "V",
                    crypto::KdfAlgorithm::Argon2,
                    &mut vdict,
                )?;
                let salt = crypto::KdfOptions::opt_from_vdict(
                    "S",
                    crypto::KdfAlgorithm::Argon2,
                    &mut vdict,
                )?;
                let iterations = crypto::KdfOptions::opt_from_vdict(
                    "I",
                    crypto::KdfAlgorithm::Argon2,
                    &mut vdict,
                )?;
                let lanes = crypto::KdfOptions::opt_from_vdict(
                    "P",
                    crypto::KdfAlgorithm::Argon2,
                    &mut vdict,
                )?;
                Ok(crypto::KdfOptions::Argon2 {
                    memory_bytes,
                    version,
                    salt,
                    iterations,
                    lanes,
                })
            }
            crypto::KdfAlgorithm::Aes256_Kdbx3_1 | crypto::KdfAlgorithm::Aes256_Kdbx4 => {
                let rounds = crypto::KdfOptions::opt_from_vdict(
                    "R",
                    crypto::KdfAlgorithm::Aes256_Kdbx4,
                    &mut vdict,
                )?;
                let salt = crypto::KdfOptions::opt_from_vdict(
                    "S",
                    crypto::KdfAlgorithm::Aes256_Kdbx4,
                    &mut vdict,
                )?;
                Ok(crypto::KdfOptions::Aes { rounds, salt })
            }
            _ => Ok(crypto::KdfOptions::Other {
                uuid: uuid.clone(),
                params: vdict,
            }),
        }
    }
}

impl Into<variant_dict::VariantDict> for crypto::KdfOptions {
    fn into(self) -> variant_dict::VariantDict {
        let mut vdict = variant_dict::VariantDict::new();
        match self {
            crypto::KdfOptions::Argon2 {
                memory_bytes,
                version,
                salt,
                lanes,
                iterations,
            } => {
                vdict.insert(
                    "$UUID".into(),
                    variant_dict::Value::Array(
                        uuid::Uuid::from(crypto::KdfAlgorithm::Aes256_Kdbx4)
                            .as_bytes()
                            .iter()
                            .cloned()
                            .collect(),
                    ),
                );
                vdict.insert("M".into(), variant_dict::Value::Uint64(memory_bytes));
                vdict.insert("I".into(), variant_dict::Value::Uint64(iterations));
                vdict.insert("V".into(), variant_dict::Value::Uint32(version));
                vdict.insert("P".into(), variant_dict::Value::Uint32(lanes));
                vdict.insert("S".into(), variant_dict::Value::Array(salt));
            }
            crypto::KdfOptions::Aes { rounds, salt } => {
                vdict.insert(
                    "$UUID".into(),
                    variant_dict::Value::Array(
                        uuid::Uuid::from(crypto::KdfAlgorithm::Aes256_Kdbx4)
                            .as_bytes()
                            .iter()
                            .cloned()
                            .collect(),
                    ),
                );
                vdict.insert("R".into(), variant_dict::Value::Uint64(rounds));
                vdict.insert("S".into(), variant_dict::Value::Array(salt));
            }
            crypto::KdfOptions::Other { uuid, params } => {
                vdict.insert(
                    "$UUID".into(),
                    variant_dict::Value::Array(uuid.as_bytes().iter().cloned().collect()),
                );
                vdict.extend(params.into_iter())
            }
        }
        vdict
    }
}

impl crypto::KdfOptions {
    fn opt_from_vdict<T>(
        key: &str,
        algo: crypto::KdfAlgorithm,
        vdict: &mut variant_dict::VariantDict,
    ) -> Result<T>
    where
        T: TryFrom<variant_dict::Value>,
    {
        vdict
            .remove(key)
            .and_then(|val| val.try_into().ok())
            .ok_or_else(|| Error::MissingKdfParam(key.to_string(), algo))
    }
}

pub const COMPRESSION_TYPE_NONE: u32 = 0;
pub const COMPRESSION_TYPE_GZIP: u32 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CompressionType {
    None,
    Gzip,
    Unknown(u32),
}

impl Into<u32> for CompressionType {
    fn into(self) -> u32 {
        match self {
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum HeaderType {
    EndOfHeader,
    Comment,
    CipherId,
    CompressionFlags,
    MasterSeed,
    LegacyTransformSeed,
    LegacyTransformRounds,
    EncryptionIv,
    ProtectedStreamKey,
    KdfParameters,
    InnerRandomStreamId,
    PublicCustomData,
    StreamStartBytes,
    Unknown(u8),
}

impl From<u8> for HeaderType {
    fn from(id: u8) -> HeaderType {
        match id {
            0 => HeaderType::EndOfHeader,
            1 => HeaderType::Comment,
            2 => HeaderType::CipherId,
            3 => HeaderType::CompressionFlags,
            4 => HeaderType::MasterSeed,
            5 => HeaderType::LegacyTransformSeed,
            6 => HeaderType::LegacyTransformRounds,
            7 => HeaderType::EncryptionIv,
            8 => HeaderType::ProtectedStreamKey,
            9 => HeaderType::StreamStartBytes,
            10 => HeaderType::InnerRandomStreamId,
            11 => HeaderType::KdfParameters,
            12 => HeaderType::PublicCustomData,
            x => HeaderType::Unknown(x),
        }
    }
}

impl Into<u8> for HeaderType {
    fn into(self) -> u8 {
        match self {
            HeaderType::EndOfHeader => 0,
            HeaderType::Comment => 1,
            HeaderType::CipherId => 2,
            HeaderType::CompressionFlags => 3,
            HeaderType::MasterSeed => 4,
            HeaderType::LegacyTransformSeed => 5,
            HeaderType::LegacyTransformRounds => 6,
            HeaderType::EncryptionIv => 7,
            HeaderType::ProtectedStreamKey => 8,
            HeaderType::StreamStartBytes => 9,
            HeaderType::InnerRandomStreamId => 10,
            HeaderType::KdfParameters => 11,
            HeaderType::PublicCustomData => 12,
            HeaderType::Unknown(x) => x,
        }
    }
}

#[derive(Default)]
pub struct KdbxHeaderBuilder {
    pub cipher: Option<crypto::Cipher>,
    pub kdf_params: Option<crypto::KdfOptions>,
    pub compression_type: Option<CompressionType>,
    pub other_headers: Vec<HeaderField>,
    pub master_seed: Option<Vec<u8>>,
    pub encryption_iv: Option<Vec<u8>>,
}

impl KdbxHeaderBuilder {
    fn add_header(&mut self, header: HeaderField) -> Result<()> {
        match header.ty {
            HeaderType::CipherId => {
                let cipher = Uuid::from_slice(&header.data)
                    .map(From::from)
                    .map_err(|_e| Error::MalformedField(header.ty))?;

                self.cipher = Some(cipher);
            }
            HeaderType::KdfParameters => {
                self.kdf_params = Some(
                    variant_dict::parse_variant_dict(&*header.data)
                        .map_err(|_| Error::MalformedField(HeaderType::KdfParameters))?
                        .try_into()?,
                );
            }
            HeaderType::CompressionFlags => {
                if header.data.len() != 4 {
                    return Err(Error::MalformedField(HeaderType::CompressionFlags));
                }
                self.compression_type = Some(CompressionType::from(u32::from_le_bytes([
                    header.data[0],
                    header.data[1],
                    header.data[2],
                    header.data[3],
                ])))
            }
            HeaderType::EncryptionIv => self.encryption_iv = Some(header.data),
            HeaderType::MasterSeed => self.master_seed = Some(header.data),
            _ => self.other_headers.push(header),
        }

        Ok(())
    }

    fn build(self) -> Result<KdbxHeader> {
        Ok(KdbxHeader {
            cipher: self
                .cipher
                .ok_or_else(|| Error::MissingRequiredField(HeaderType::CipherId))?,
            compression_type: self
                .compression_type
                .ok_or_else(|| Error::MissingRequiredField(HeaderType::CompressionFlags))?,
            master_seed: self
                .master_seed
                .ok_or_else(|| Error::MissingRequiredField(HeaderType::MasterSeed))?,
            encryption_iv: self
                .encryption_iv
                .ok_or_else(|| Error::MissingRequiredField(HeaderType::EncryptionIv))?,
            kdf_params: self
                .kdf_params
                .ok_or_else(|| Error::MissingRequiredField(HeaderType::KdfParameters))?,
            other_headers: self.other_headers,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HeaderField {
    ty: HeaderType,
    data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KdbxHeader {
    pub cipher: crypto::Cipher,
    pub kdf_params: crypto::KdfOptions,
    pub compression_type: CompressionType,
    pub other_headers: Vec<HeaderField>,
    pub master_seed: Vec<u8>,
    pub encryption_iv: Vec<u8>,
}

impl KdbxHeader {
    pub(crate) fn read_one_header<R: Read>(
        caching_reader: &mut utils::CachingReader<R>,
    ) -> Result<HeaderField> {
        let mut ty_buffer = [0u8];
        caching_reader.read_exact(&mut ty_buffer)?;
        let ty = HeaderType::from(ty_buffer[0]);
        let mut len_buffer = [0u8; 4];
        caching_reader.read_exact(&mut len_buffer)?;
        let len = u32::from_le_bytes(len_buffer.clone());
        let mut header_buffer = utils::buffer(len as usize);
        caching_reader.read_exact(&mut header_buffer)?;

        Ok(HeaderField {
            ty,
            data: header_buffer,
        })
    }

    pub(crate) fn read<R: Read>(
        mut caching_reader: utils::CachingReader<R>,
    ) -> Result<(KdbxHeader, Vec<u8>)> {
        let mut header_builder = KdbxHeaderBuilder::default();

        let mut header = KdbxHeader::read_one_header(&mut caching_reader)?;
        while header.ty != HeaderType::EndOfHeader {
            header_builder.add_header(header)?;
            header = KdbxHeader::read_one_header(&mut caching_reader)?;
        }

        let (header_bin, input) = caching_reader.into_inner();

        let mut sha = utils::buffer(Sha256::output_size());
        input.read_exact(&mut sha)?;

        if crypto::verify_sha256(&header_bin, &sha) {
            Ok((header_builder.build()?, header_bin))
        } else {
            Err(Error::ChecksumFailed)
        }
    }
}
