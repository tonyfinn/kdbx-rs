//! Error types for kdbx-rs

pub use crate::binary::errors::{HeaderError, OpenError, UnlockError};
pub use crate::xml::parse::Error as XmlError;
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
    Xml(#[from] XmlError),
}
