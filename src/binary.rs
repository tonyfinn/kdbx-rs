//! .kdbx archives and the outer binary format
//!
//! Most methods are available on a specific state like `Kdbx<Locked>`
//! or `Kdbx<Unlocked>`.
//!
//! A keepass 2 archive can be obtained in one of two ways. You may read
//! an existing archive using [`kdbx_rs::open`][crate::open] or
//! [`kdbx_rs::from_reader`][crate::from_reader].
//!
//! You can also create a password database using [`Database`][crate::Database],
//! then turn it into a KeePass 2 archive using [`Kdbx::from_database`].

pub(crate) mod errors;
mod header;
mod header_fields;
pub(crate) mod kdb;
mod kdbx;
mod read;
mod variant_dict;

pub use header::{InnerHeaderId, KdbxHeader, KdbxInnerHeader, OuterHeaderId};
pub use header_fields::{
    Cipher, CompressionType, InnerStreamCipherAlgorithm, KdfAlgorithm, KdfParams,
};
pub(crate) use header_fields::{KDBX_MAGIC_NUMBER, KDB_MAGIC_NUMBER, KEEPASS_MAGIC_NUMBER};
pub use kdbx::{FailedUnlock, Kdbx, Locked, Unlocked};
pub use read::{from_reader, open};
pub use variant_dict::{Value as VariantDictValue, VariantDict, VariantParseError};
