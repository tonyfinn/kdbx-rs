//! Error types for kdbx-rs

pub use crate::binary::errors::{
    HeaderError, OpenError, UnlockError, WriteError,
};
pub use crate::binary::FailedUnlock;
pub use crate::crypto::KeyGenerationError;
pub use crate::xml::parse::Error as XmlReadError;
pub use crate::xml::serialize::Error as XmlWriteError;
use thiserror::Error;

#[derive(Error, Debug)]
/// Wrapper error type for this library
pub enum Error {
    /// Failed to open a KDBX file
    #[error("Could not open database: {0}")]
    Open(#[from] OpenError),
    /// Failed unlocking a KDBX file
    #[error("Could not unlock database: {0}")]
    Unlock(#[from] UnlockError),
    /// Failed to write a KDBX file
    #[error("Could not write database: {0}")]
    Write(#[from] WriteError),
    /// Failed parsing database XML
    #[error("Failed to parse database XML: {0}")]
    XmlRead(#[from] XmlReadError),
    /// Failed writing database XML
    #[error("Failed to write database XML: {0}")]
    XmlWrite(#[from] XmlWriteError),
    /// Failed generating crypto keys
    #[error("Failed to create encryption keys")]
    KeyGeneration(#[from] KeyGenerationError),
}

impl From<FailedUnlock> for Error {
    fn from(funlock: FailedUnlock) -> Error {
        Error::Unlock(funlock.1)
    }
}
