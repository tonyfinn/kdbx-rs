use crate::crypto;
use crate::header;
use crate::stream;
use crate::utils;

use sha2::{Digest, Sha256};
use std::io::Read;
use thiserror::Error;

pub const KEEPASS_MAGIC_NUMBER: u32 = 0x9AA2D903;
pub const KDBX_MAGIC_NUMBER: u32 = 0xB54BFB67;

#[derive(Error, Debug)]
pub enum OpenError {
    #[error("Unsupported file type - not a keepass database")]
    NonKeepassFormat,
    #[error("Unsupported file type - not kdbx")]
    UnsupportedFileFormat,
    #[error("Unsupported kdbx version {0}")]
    UnsupportedMajorVersion(u16),
    #[error("Error reading database header: {0}")]
    InvalidHeader(#[from] header::Error),
    #[error("IO error reading file: {0}")]
    Io(#[from] std::io::Error),
}

pub trait DatabaseState: std::fmt::Debug {}

#[derive(Debug)]
/// State machine representing a kdbx database
///
/// Most methods are available on a specific state
/// like KdbxDatabase<Locked> or KdbxDatase<Unlocked>
pub struct KdbxDatabase<S>
where
    S: DatabaseState,
{
    inner: S,
}

#[derive(Debug)]
pub struct Unlocked {
    /// Header data of the kdbx archive, includes unencrypted metadata
    pub header: header::KdbxHeader,
    #[doc(hidden)]
    pub decrypted_data: Vec<u8>,
}

impl DatabaseState for Unlocked {}

impl KdbxDatabase<Unlocked> {
    /// Returns database header information
    pub fn header(&self) -> &header::KdbxHeader {
        &self.inner.header
    }

    pub fn decrypted_data(&self) -> &[u8] {
        &self.inner.decrypted_data
    }
}

#[derive(Debug, Error)]
pub enum UnlockError {
    #[error("Header validation failed - wrong password or corrupt database")]
    HmacInvalid,
    #[error("Key generation failed {0}")]
    KeyGen(#[from] crypto::KeyGenerationError),
    #[error("Decryption failed {0}")]
    Decrypt(#[from] std::io::Error),
}

#[derive(Debug, PartialEq, Eq)]
/// A locked database, use unlock(composite_key) to unlock
pub struct Locked {
    /// Header data of the kdbx archive, includes unencrypted metadata
    pub header: header::KdbxHeader,
    /// Raw bytes of header data, useful for checksums
    pub header_data: Vec<u8>,
    /// Major version of the database file format
    pub major_version: u16,
    /// Minor version of the database file format
    pub minor_version: u16,
    /// hmac code to verify keys and header integrity
    pub hmac: Vec<u8>,
    /// Encrypted vault data
    pub encrypted_data: Vec<u8>,
}

impl DatabaseState for Locked {}

impl KdbxDatabase<Locked> {
    /// Returns database header information
    pub fn header(&self) -> &header::KdbxHeader {
        &self.inner.header
    }

    pub(crate) fn decrypt_data(
        &self,
        master_key: &crypto::MasterKey,
    ) -> Result<Vec<u8>, UnlockError> {
        let hmac_key = master_key.hmac_key(&self.inner.header.master_seed);
        let cipher_key = master_key.cipher_key(&self.inner.header.master_seed);
        let mut input_stream = stream::kdbx4_read_stream(
            &*self.inner.encrypted_data,
            hmac_key,
            cipher_key,
            self.inner.header.cipher,
            &self.inner.header.encryption_iv,
            self.inner.header.compression_type,
        )?;
        let mut output_buffer = Vec::new();
        input_stream.read_to_end(&mut output_buffer)?;
        Ok(output_buffer)
    }

    /// Unlocks the database
    ///
    /// If unlock fails, returns the locked database along with the error
    pub fn unlock(
        self,
        key: crypto::CompositeKey,
    ) -> Result<KdbxDatabase<Unlocked>, (UnlockError, KdbxDatabase<Locked>)> {
        let master_key = match key.master_key(&self.inner.header.kdf_params) {
            Ok(master_key) => master_key,
            Err(e) => return Err((UnlockError::from(e), self)),
        };

        let hmac_key = master_key.hmac_key(&self.inner.header.master_seed);
        let header_block_key = hmac_key.block_key(u64::MAX);

        if header_block_key.verify_header_block(&self.inner.hmac, &self.inner.header_data) {
            match self.decrypt_data(&master_key) {
                Ok(data) => Ok(KdbxDatabase {
                    inner: Unlocked {
                        header: self.inner.header,
                        decrypted_data: data,
                    },
                }),
                Err(e) => Err((e, self)),
            }
        } else {
            Err((UnlockError::HmacInvalid, self))
        }
    }
}

/// Read a database from a file
///
/// The database starts locked, use unlock() to unlock
pub fn read<R: Read>(mut input: R) -> Result<KdbxDatabase<Locked>, OpenError> {
    let mut caching_reader = utils::CachingReader::new(&mut input);
    let mut buffer = [0u8; 4];
    caching_reader.read_exact(&mut buffer)?;

    if u32::from_le_bytes(buffer) != KEEPASS_MAGIC_NUMBER {
        return Err(OpenError::NonKeepassFormat);
    }

    caching_reader.read_exact(&mut buffer)?;

    if u32::from_le_bytes(buffer) != KDBX_MAGIC_NUMBER {
        return Err(OpenError::UnsupportedFileFormat);
    }

    caching_reader.read_exact(&mut buffer)?;

    let minor_version = u16::from_le_bytes([buffer[0], buffer[1]]);
    let major_version = u16::from_le_bytes([buffer[2], buffer[3]]);

    if major_version != 4 {
        return Err(OpenError::UnsupportedMajorVersion(major_version));
    }

    let (header, header_data) = header::KdbxHeader::read(caching_reader)?;

    let mut hmac = utils::buffer(Sha256::output_size());
    input.read_exact(&mut hmac)?;
    let mut encrypted_data = Vec::new();
    input.read_to_end(&mut encrypted_data)?;

    let state = Locked {
        header,
        header_data,
        major_version,
        minor_version,
        hmac,
        encrypted_data,
    };

    Ok(KdbxDatabase { inner: state })
}
