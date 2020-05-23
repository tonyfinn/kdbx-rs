use super::errors::HeaderError as Error;
use super::header_fields;
use super::variant_dict;
use crate::crypto;
use crate::utils;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::io::{Read, Write};
use std::marker::PhantomData;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Error>;

pub trait HeaderId: From<u8> + Into<u8> {
    fn is_final(&self) -> bool;
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
/// Field types for unencrypted header
pub enum OuterHeaderId {
    /// Last header field
    EndOfHeader,
    /// Custom comment to describe the database
    Comment,
    /// UUID indicating the cipher for the database
    CipherId,
    /// Compression algorithm in use
    CompressionFlags,
    /// Seed to make database keys unique
    MasterSeed,
    /// KDBX3 only - Seed used for converting passwords to keys
    LegacyTransformSeed,
    /// KDBX3 only - Number of rounds of aes256 to use to generate keys
    LegacyTransformRounds,
    /// Initial value for encrypting/decrypting the stream
    EncryptionIv,
    /// KDBX3 only - Key used for decrypting inner streams
    ProtectedStreamKey,
    /// KDBX3 only - First 32 bytes of decrypted data, newer databases have a HMAC
    StreamStartBytes,
    /// KDBX3 only - Cipher identifer for data encrypted in memory
    InnerRandomStreamId,
    /// KDBX4 only - Parameters used to convert credentials to keys
    KdfParameters,
    /// KDBX4 only - Unencrypted custom data for plugins
    PublicCustomData,
    /// Some header field not supported by this library
    Unknown(u8),
}

impl From<u8> for OuterHeaderId {
    fn from(id: u8) -> OuterHeaderId {
        match id {
            0 => OuterHeaderId::EndOfHeader,
            0x1 => OuterHeaderId::Comment,
            0x2 => OuterHeaderId::CipherId,
            0x3 => OuterHeaderId::CompressionFlags,
            0x4 => OuterHeaderId::MasterSeed,
            0x5 => OuterHeaderId::LegacyTransformSeed,
            0x6 => OuterHeaderId::LegacyTransformRounds,
            0x7 => OuterHeaderId::EncryptionIv,
            0x8 => OuterHeaderId::ProtectedStreamKey,
            0x9 => OuterHeaderId::StreamStartBytes,
            0xA => OuterHeaderId::InnerRandomStreamId,
            0xB => OuterHeaderId::KdfParameters,
            0xC => OuterHeaderId::PublicCustomData,
            x => OuterHeaderId::Unknown(x),
        }
    }
}

impl Into<u8> for OuterHeaderId {
    fn into(self) -> u8 {
        match self {
            OuterHeaderId::EndOfHeader => 0,
            OuterHeaderId::Comment => 0x1,
            OuterHeaderId::CipherId => 0x2,
            OuterHeaderId::CompressionFlags => 0x3,
            OuterHeaderId::MasterSeed => 0x4,
            OuterHeaderId::LegacyTransformSeed => 0x5,
            OuterHeaderId::LegacyTransformRounds => 0x6,
            OuterHeaderId::EncryptionIv => 0x7,
            OuterHeaderId::ProtectedStreamKey => 0x8,
            OuterHeaderId::StreamStartBytes => 0x9,
            OuterHeaderId::InnerRandomStreamId => 0xA,
            OuterHeaderId::KdfParameters => 0xB,
            OuterHeaderId::PublicCustomData => 0xC,
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
/// Field types for encrypted inner header
pub enum InnerHeaderId {
    /// Last field in the header
    EndOfHeader,
    /// Cipher identifier for data encrypted in memory
    InnerRandomStreamCipherId,
    /// Cipher key for data encrypted in memory
    InnerRandomStreamKey,
    /// Binary data in the header
    Binary,
    /// Header unknown to this library
    Unknown(u8),
}

impl From<u8> for InnerHeaderId {
    fn from(id: u8) -> InnerHeaderId {
        match id {
            0 => InnerHeaderId::EndOfHeader,
            1 => InnerHeaderId::InnerRandomStreamCipherId,
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
            InnerHeaderId::InnerRandomStreamCipherId => 1,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderField<T> {
    ty: T,
    data: Vec<u8>,
}

impl<T> HeaderField<T> {
    pub(crate) fn new(ty: T, data: Vec<u8>) -> HeaderField<T> {
        HeaderField { ty, data }
    }
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

#[derive(Default)]
pub struct KdbxHeaderBuilder {
    pub cipher: Option<header_fields::Cipher>,
    pub kdf_params: Option<header_fields::KdfParams>,
    pub compression_type: Option<header_fields::CompressionType>,
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
                    .map_err(|_e| {
                        Error::MalformedField(header.ty, "Cipher UUID not valid".into())
                    })?;

                self.cipher = Some(cipher);
            }
            OuterHeaderId::KdfParameters => {
                self.kdf_params = match variant_dict::parse_variant_dict(&*header.data) {
                    Ok(vdict) => Some(vdict.try_into()?),
                    Err(e) => {
                        println!("Malformed field: {}", e);
                        return Err(Error::MalformedField(
                            OuterHeaderId::KdfParameters,
                            "Corrupt variant dictionary".into(),
                        ));
                    }
                };
            }
            OuterHeaderId::CompressionFlags => {
                if header.data.len() != 4 {
                    return Err(Error::MalformedField(
                        OuterHeaderId::CompressionFlags,
                        "Wrong size for compression ID".into(),
                    ));
                }
                self.compression_type =
                    Some(header_fields::CompressionType::from(u32::from_le_bytes([
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
/// Unencrypted database configuration and custom data
///
/// [`KdbxHeader::from_os_random()`] will provide a header with
/// the default encryption settings and new random keys
/// from the OS secure RNG
pub struct KdbxHeader {
    /// Encryption cipher used for decryption the database
    pub cipher: header_fields::Cipher,
    /// Options for converting credentials to crypto keys
    pub kdf_params: header_fields::KdfParams,
    /// Compression applied prior to encryption
    pub compression_type: header_fields::CompressionType,
    /// Custom and unrecognized header types
    pub other_headers: Vec<HeaderField<OuterHeaderId>>,
    /// Master seed used to make crypto keys DB specific
    pub master_seed: Vec<u8>,
    /// IV used for initializing crypto
    pub encryption_iv: Vec<u8>,
}

impl KdbxHeader {
    /// Create a new header to encrypt a database with keys from the OS Secure RNG.
    ///
    /// Under the hood this uses the [`rand`] crate to access the [`OsRng`],
    /// the actual mechanism used to get random numbers is detailed in that
    /// crate's documentation.
    ///
    /// The default encryption is currently to use AES256 as a stream cipher,
    /// and Argon2d v19 with 64 MiB memory factor, and 10 iterations as the KDF.
    /// This is subject to change in future crate versions
    ///
    /// [`rand`]: https://docs.rs/rand/
    /// [`OsRng`]: https://docs.rs/rand/0.7/rand/rngs/struct.OsRng.html
    pub fn from_os_random() -> KdbxHeader {
        let mut master_seed = vec![0u8; 32];
        let mut encryption_iv = vec![0u8; 16];
        let mut cipher_salt = vec![0u8; 32];
        OsRng.fill_bytes(&mut master_seed);
        OsRng.fill_bytes(&mut encryption_iv);
        OsRng.fill_bytes(&mut cipher_salt);
        KdbxHeader {
            cipher: header_fields::Cipher::Aes256,
            kdf_params: header_fields::KdfParams::Argon2 {
                iterations: 10,
                memory_bytes: 0xFFFF * 1024,
                salt: cipher_salt,
                version: 19,
                lanes: 2,
            },
            other_headers: Vec::new(),
            compression_type: super::CompressionType::None,
            master_seed,
            encryption_iv,
        }
    }

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

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        use std::iter::once;
        let headers = self
            .other_headers
            .iter()
            .cloned()
            .chain(once(self.cipher.into()))
            .chain(once(self.compression_type.clone().into()))
            .chain(once(HeaderField::new(
                OuterHeaderId::MasterSeed,
                self.master_seed.clone(),
            )))
            .chain(once(HeaderField::new(
                OuterHeaderId::EncryptionIv,
                self.encryption_iv.clone(),
            )))
            .chain(once(self.kdf_params.clone().into()))
            .chain(once(HeaderField::new(
                OuterHeaderId::EndOfHeader,
                Vec::new(),
            )));

        for header in headers {
            writer.write_all(&[header.ty.into()])?;
            writer.write_all(&(header.data.len() as u32).to_le_bytes())?;
            writer.write_all(&header.data)?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct KdbxInnerHeaderBuilder {
    pub inner_stream_cipher: Option<header_fields::InnerStreamCipherAlgorithm>,
    pub inner_stream_key: Option<Vec<u8>>,
    /// Custom and unrecognized header types
    pub other_headers: Vec<HeaderField<InnerHeaderId>>,
}

impl KdbxInnerHeaderBuilder {
    fn add_header(&mut self, header: HeaderField<InnerHeaderId>) -> Result<()> {
        match header.ty {
            InnerHeaderId::InnerRandomStreamCipherId => {
                let d = header.data;
                self.inner_stream_cipher =
                    Some(u32::from_le_bytes([d[0], d[1], d[2], d[3]]).into());
            }
            InnerHeaderId::InnerRandomStreamKey => self.inner_stream_key = Some(header.data),
            _ => self.other_headers.push(header),
        }

        Ok(())
    }

    fn build(self) -> Result<KdbxInnerHeader> {
        Ok(KdbxInnerHeader {
            inner_stream_cipher: self.inner_stream_cipher.ok_or_else(|| {
                Error::MissingRequiredInnerField(InnerHeaderId::InnerRandomStreamCipherId)
            })?,
            inner_stream_key: self.inner_stream_key.ok_or_else(|| {
                Error::MissingRequiredInnerField(InnerHeaderId::InnerRandomStreamKey)
            })?,
            other_headers: self.other_headers,
        })
    }
}

/// Encrypted database information and custom data
#[derive(Debug, PartialEq, Eq)]
pub struct KdbxInnerHeader {
    /// Cipher identifier for data encrypted in memory
    pub inner_stream_cipher: header_fields::InnerStreamCipherAlgorithm,
    /// Cipher key for data encrypted in memory
    pub inner_stream_key: Vec<u8>,
    /// Headers not handled by this library
    pub other_headers: Vec<HeaderField<InnerHeaderId>>,
}

impl KdbxInnerHeader {
    /// Returns an inner header setup for a default stream cipher and OS random keys
    ///
    /// Currently the default stream cipher is ChaCha20
    ///
    /// Under the hood this uses the [`rand`] crate to access the [`OsRng`],
    /// the actual mechanism used to get random numbers is detailed in that
    /// crate's documentation.
    ///
    /// [`rand`]: https://docs.rs/rand/
    /// [`OsRng`]: https://docs.rs/rand/0.7/rand/rngs/struct.OsRng.html
    pub fn from_os_random() -> KdbxInnerHeader {
        let inner_stream_cipher = header_fields::InnerStreamCipherAlgorithm::ChaCha20;
        let mut inner_stream_key = vec![0u8; 44]; // 32 bit key + 12 bit nonce for chacha20
        OsRng.fill_bytes(&mut inner_stream_key);

        KdbxInnerHeader {
            inner_stream_cipher,
            inner_stream_key,
            other_headers: Vec::new(),
        }
    }

    pub(crate) fn read<R: Read>(reader: &mut R) -> Result<KdbxInnerHeader> {
        let mut header_builder = KdbxInnerHeaderBuilder::default();
        let headers = HeaderParser::new(reader).read_all_headers()?;
        for header in headers {
            header_builder.add_header(header)?;
        }

        header_builder.build()
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        use std::iter::once;
        let headers = self
            .other_headers
            .iter()
            .cloned()
            .chain(once(self.inner_stream_cipher.clone().into()))
            .chain(once(HeaderField::new(
                InnerHeaderId::InnerRandomStreamKey,
                self.inner_stream_key.clone(),
            )))
            .chain(once(HeaderField::new(
                InnerHeaderId::EndOfHeader,
                Vec::new(),
            )));

        for header in headers {
            writer.write_all(&[header.ty.into()])?;
            writer.write_all(&(header.data.len() as i32).to_le_bytes())?;
            writer.write_all(&header.data)?;
        }
        Ok(())
    }
}
