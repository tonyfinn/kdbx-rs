#![deny(missing_docs)]

//! Module to read and write KDBX (Keepass 2) database files.
//!
//! Databases can be read with the [`kdbx_rs::open`] function. This provides
//! access to heder information. It can then be unlocked by providing a [`CompositeKey`]
//! to the [`KdbxDatabase.unlock`] method to access any encrypted data.
//!
//! ```
//! # fn main() -> Result<(), kdbx_rs::Error> {
//! use kdbx_rs::CompositeKey;
//!
//! # let file_path = "./res/kdbx4-argon2.kdbx";
//! let db = kdbx_rs::open(file_path)?;
//! let key = CompositeKey::from_password("kdbxrs");
//! // If unlock fails, the locked database is returned to you
//! // so you can e.g. prompt the user to try another password
//! //
//! // Here we just return if incorrect
//! let unlocked = db.unlock(&key).map_err(|(error, locked)| error)?;
//! # Ok(())
//! # }
//! ```
//!
//! Alternatively, [`kdbx_rs::from_reader`] can be used to open a database
//! from a non file source (such as in-memory or a network stream)
//!
//! [`CompositeKey`]: ./struct.CompositeKey.html
//! [`kdbx_rs::from_reader`]: ./fn.from_reader.html
//! [`kdbx_rs::open`]: ./fn.open.html
//! [`KdbxDatabase.unlock`]: ./struct.KdbxDatabase.html#method.unlock

pub mod binary;
mod crypto;
pub mod errors;
mod stream;
mod utils;
pub mod xml;

pub use crate::xml::{parse_xml, XmlDatabase};
pub use binary::{from_reader, open, KdbxDatabase};
pub use crypto::CompositeKey;
pub use errors::Error;
