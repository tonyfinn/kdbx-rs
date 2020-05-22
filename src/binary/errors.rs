use super::header;
use super::wrapper_fields;
use crate::crypto;
use thiserror::Error;

#[derive(Error, Debug)]
/// Errors encountered loading a database prior to decryption
pub enum OpenError {
    /// Keepass database magic number missing
    #[error("Unsupported file type - not a keepass database")]
    NonKeepassFormat,
    /// Second header magic number is not that for kdbx (possibly kdb)
    #[error("Unsupported file type - not kdbx")]
    UnsupportedFileFormat,
    /// The KDBX version is not v3 or v4
    #[error("Unsupported kdbx version {0}")]
    UnsupportedMajorVersion(u16),
    /// There was some error parsing the unencrypted database header
    #[error("Error reading database header - {0}")]
    InvalidHeader(#[from] HeaderError),
    /// Error encountered reading database
    #[error("IO error reading file - {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
/// Errors encountered unlocking a encrypted database
pub enum UnlockError {
    /// The HMAC signature check failed. This indicates an invalid password or corrupt DB
    #[error("Header validation failed - wrong password or corrupt database")]
    HmacInvalid,
    /// There was some error generating the keys, likely incorrect or unsupported KDF options
    #[error("Key generation failed - {0}")]
    KeyGen(#[from] crypto::KeyGenerationError),
    /// Error encountered decrypting the database content
    #[error("Decryption failed - {0}")]
    Decrypt(#[from] std::io::Error),
    /// The inner header is invalid
    #[error("Inner header invalid - {0}")]
    InvalidInnerHeader(#[from] HeaderError),
    /// The inner header is invalid
    #[error("Corrupt database. XML data is invald - {0}")]
    InvalidXml(#[from] crate::errors::XmlReadError),
}

#[derive(Debug, Error)]
/// Errors uncountering validating the database header
pub enum HeaderError {
    /// The reader failed before the header was entirely read
    #[error("Error reading database header - {0}")]
    Io(#[from] std::io::Error),
    /// A supported field had an unexpected format
    #[error("Incompatible database - Malformed field of type {0:?}")]
    MalformedField(header::OuterHeaderId),
    /// A required field is missing in the unencrypted header
    #[error("Incompatible database - Missing required field of type {0:?}")]
    MissingRequiredField(header::OuterHeaderId),
    /// A required field is missing in the encrypted header
    #[error("Incompatible database - Missing required inner field of type {0:?}")]
    MissingRequiredInnerField(header::InnerHeaderId),
    /// A parameter for the KDF algorithm is missing
    #[error("Incompatible database - Missing paramater {0:?} for KDF {1:?}")]
    MissingKdfParam(String, wrapper_fields::KdfAlgorithm),
    /// Validating the header against the unencrypted sha256 hash failed
    #[error("Corrupt database - Header Checksum failed")]
    ChecksumFailed,
    /// The database cipher is not supported by this library.
    #[error("Incompatible database - Unknown cipher {0:?}")]
    UnknownCipher(uuid::Uuid),
}

#[derive(Debug, Error)]
/// Errors encountered writing a database
pub enum WriteError {
    /// The reader failed before the header was entirely read
    #[error("Error reading database header - {0}")]
    Io(#[from] std::io::Error),
    /// The database could not be serialized to XML
    #[error("Error serializing database to XML - {0}")]
    XmlWrite(#[from] crate::xml::serialize::Error),
    /// The database could not be written to as `set_key()` has not been called.
    #[error("No key to write database with")]
    MissingKeys,
}

#[derive(Debug, Error)]
/// Errors encountered writing a database
pub enum DatabaseCreationError {
    /// Could not obtain secure random data
    #[error("Error getting RNG data for keys")]
    Random(#[from] getrandom::Error),
}
