use crate::crypto;
use crate::utils;
use crate::variant_dict;
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use std::io::Read;
use std::marker::PhantomData;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error reading database header - {0}")]
    Io(#[from] std::io::Error),
    #[error("Incompatible database - Malformed field of type {0:?}")]
    MalformedField(OuterHeaderId),
    #[error("Incompatible database - Missing required field of type {0:?}")]
    MissingRequiredField(OuterHeaderId),
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
            .ok_or_else(|| Error::MalformedField(OuterHeaderId::KdfParameters))?;

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

pub trait HeaderId: From<u8> + Into<u8> {
    fn is_final(&self) -> bool;
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum OuterHeaderId {
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

impl From<u8> for OuterHeaderId {
    fn from(id: u8) -> OuterHeaderId {
        match id {
            0 => OuterHeaderId::EndOfHeader,
            1 => OuterHeaderId::Comment,
            2 => OuterHeaderId::CipherId,
            3 => OuterHeaderId::CompressionFlags,
            4 => OuterHeaderId::MasterSeed,
            5 => OuterHeaderId::LegacyTransformSeed,
            6 => OuterHeaderId::LegacyTransformRounds,
            7 => OuterHeaderId::EncryptionIv,
            8 => OuterHeaderId::ProtectedStreamKey,
            9 => OuterHeaderId::StreamStartBytes,
            10 => OuterHeaderId::InnerRandomStreamId,
            11 => OuterHeaderId::KdfParameters,
            12 => OuterHeaderId::PublicCustomData,
            x => OuterHeaderId::Unknown(x),
        }
    }
}

impl Into<u8> for OuterHeaderId {
    fn into(self) -> u8 {
        match self {
            OuterHeaderId::EndOfHeader => 0,
            OuterHeaderId::Comment => 1,
            OuterHeaderId::CipherId => 2,
            OuterHeaderId::CompressionFlags => 3,
            OuterHeaderId::MasterSeed => 4,
            OuterHeaderId::LegacyTransformSeed => 5,
            OuterHeaderId::LegacyTransformRounds => 6,
            OuterHeaderId::EncryptionIv => 7,
            OuterHeaderId::ProtectedStreamKey => 8,
            OuterHeaderId::StreamStartBytes => 9,
            OuterHeaderId::InnerRandomStreamId => 10,
            OuterHeaderId::KdfParameters => 11,
            OuterHeaderId::PublicCustomData => 12,
            OuterHeaderId::Unknown(x) => x,
        }
    }
}

impl HeaderId for OuterHeaderId {
    fn is_final(&self) -> bool {
        return *self == OuterHeaderId::EndOfHeader;
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum InnerHeaderId {
    EndOfHeader,
    InnerRandomStreamId,
    InnerRandomStreamKey,
    Binary,
    Unknown(u8),
}

impl From<u8> for InnerHeaderId {
    fn from(id: u8) -> InnerHeaderId {
        match id {
            0 => InnerHeaderId::EndOfHeader,
            1 => InnerHeaderId::InnerRandomStreamId,
            2 => InnerHeaderId::InnerRandomStreamKey,
            3 => InnerHeaderId::Binary,
            x => InnerHeaderId::Unknown(x),
        }
    }
}

impl Into<u8> for InnerHeaderId {
    fn into(self) -> u8 {
        match self {
            InnerHeaderId::EndOfHeader => 0,
            InnerHeaderId::InnerRandomStreamId => 1,
            InnerHeaderId::InnerRandomStreamKey => 2,
            InnerHeaderId::Binary => 3,
            InnerHeaderId::Unknown(x) => x,
        }
    }
}

impl HeaderId for InnerHeaderId {
    fn is_final(&self) -> bool {
        return *self == InnerHeaderId::EndOfHeader;
    }
}

#[derive(Default)]
pub struct KdbxHeaderBuilder {
    pub cipher: Option<crypto::Cipher>,
    pub kdf_params: Option<crypto::KdfOptions>,
    pub compression_type: Option<CompressionType>,
    pub other_headers: Vec<HeaderField<OuterHeaderId>>,
    pub master_seed: Option<Vec<u8>>,
    pub encryption_iv: Option<Vec<u8>>,
}

impl KdbxHeaderBuilder {
    fn add_header(&mut self, header: HeaderField<OuterHeaderId>) -> Result<()> {
        match header.ty {
            OuterHeaderId::CipherId => {
                let cipher = Uuid::from_slice(&header.data)
                    .map(From::from)
                    .map_err(|_e| Error::MalformedField(header.ty))?;

                self.cipher = Some(cipher);
            }
            OuterHeaderId::KdfParameters => {
                self.kdf_params = Some(
                    variant_dict::parse_variant_dict(&*header.data)
                        .map_err(|_| Error::MalformedField(OuterHeaderId::KdfParameters))?
                        .try_into()?,
                );
            }
            OuterHeaderId::CompressionFlags => {
                if header.data.len() != 4 {
                    return Err(Error::MalformedField(OuterHeaderId::CompressionFlags));
                }
                self.compression_type = Some(CompressionType::from(u32::from_le_bytes([
                    header.data[0],
                    header.data[1],
                    header.data[2],
                    header.data[3],
                ])))
            }
            OuterHeaderId::EncryptionIv => self.encryption_iv = Some(header.data),
            OuterHeaderId::MasterSeed => self.master_seed = Some(header.data),
            _ => self.other_headers.push(header),
        }

        Ok(())
    }

    fn build(self) -> Result<KdbxHeader> {
        Ok(KdbxHeader {
            cipher: self
                .cipher
                .ok_or_else(|| Error::MissingRequiredField(OuterHeaderId::CipherId))?,
            compression_type: self
                .compression_type
                .ok_or_else(|| Error::MissingRequiredField(OuterHeaderId::CompressionFlags))?,
            master_seed: self
                .master_seed
                .ok_or_else(|| Error::MissingRequiredField(OuterHeaderId::MasterSeed))?,
            encryption_iv: self
                .encryption_iv
                .ok_or_else(|| Error::MissingRequiredField(OuterHeaderId::EncryptionIv))?,
            kdf_params: self
                .kdf_params
                .ok_or_else(|| Error::MissingRequiredField(OuterHeaderId::KdfParameters))?,
            other_headers: self.other_headers,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HeaderField<T> {
    ty: T,
    data: Vec<u8>,
}

pub struct HeaderParser<'a, R: Read + 'a, T: HeaderId> {
    _id: PhantomData<T>,
    reader: &'a mut R,
}

impl<'a, R, T> HeaderParser<'a, R, T>
where
    R: Read + 'a,
    T: HeaderId,
{
    pub(crate) fn new(reader: &'a mut R) -> HeaderParser<'a, R, T> {
        HeaderParser {
            _id: PhantomData,
            reader,
        }
    }

    pub(crate) fn read_one_header(&mut self) -> Result<HeaderField<T>> {
        let mut ty_buffer = [0u8];
        self.reader.read_exact(&mut ty_buffer)?;
        let ty = T::from(ty_buffer[0]);
        let mut len_buffer = [0u8; 4];
        self.reader.read_exact(&mut len_buffer)?;
        let len = u32::from_le_bytes(len_buffer.clone());
        let mut header_buffer = utils::buffer(len as usize);
        self.reader.read_exact(&mut header_buffer)?;

        Ok(HeaderField {
            ty,
            data: header_buffer,
        })
    }

    pub(crate) fn read_all_headers(&mut self) -> Result<Vec<HeaderField<T>>> {
        let mut headers = Vec::new();
        let mut header = self.read_one_header()?;
        while !header.ty.is_final() {
            headers.push(header);
            header = self.read_one_header()?;
        }

        Ok(headers)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct KdbxHeader {
    pub cipher: crypto::Cipher,
    pub kdf_params: crypto::KdfOptions,
    pub compression_type: CompressionType,
    pub other_headers: Vec<HeaderField<OuterHeaderId>>,
    pub master_seed: Vec<u8>,
    pub encryption_iv: Vec<u8>,
}

impl KdbxHeader {
    pub(crate) fn read<R: Read>(
        mut caching_reader: utils::CachingReader<R>,
    ) -> Result<(KdbxHeader, Vec<u8>)> {
        let mut header_builder = KdbxHeaderBuilder::default();
        let headers = HeaderParser::new(&mut caching_reader).read_all_headers()?;
        for header in headers {
            header_builder.add_header(header)?;
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
