//! Error types for kdbx-rs

pub use crate::binary::errors::{
    DatabaseCreationError, HeaderError, OpenError, UnlockError, WriteError,
};
pub use crate::crypto::KeyGenerationError;
pub use crate::xml::parse::Error as XmlReadError;
pub use crate::xml::serialize::Error as XmlWriteError;
use thiserror::Error;

#[derive(Error, Debug)]
/// Wrapper error type for this library
pub enum Error {
    /// Failed to open a database
    #[error("Could not open database: {0}")]
    Open(#[from] OpenError),
    /// Failed unlocking a database
    #[error("Could not unlock database: {0}")]
    Unlock(#[from] UnlockError),
    /// Failed parsing database XML
    #[error("Failed to parse database XML: {0}")]
    XmlRead(#[from] XmlReadError),
    /// Failed writing database XML
    #[error("Failed to write database XML: {0}")]
    XmlWrite(#[from] XmlWriteError),
    /// Failed to create a database in memory
    #[error("Failed to create database: {0}")]
    Creation(#[from] DatabaseCreationError),
    /// Failed generating crypto keys
    #[error("Failed to create encryption keys")]
    KeyGeneration(#[from] KeyGenerationError),
}
