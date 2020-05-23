//! .kdbx files and the outer binary format

pub(crate) mod errors;
mod header;
mod header_fields;
mod read;
mod kdbx;
mod variant_dict;

pub use header::{InnerHeaderId, KdbxHeader, KdbxInnerHeader, OuterHeaderId};
pub use read::{from_reader, open};
pub use kdbx::{Kdbx, Locked, Unlocked, FailedUnlock};
pub use variant_dict::{Value as VariantDictValue, VariantDict, VariantParseError};
pub use header_fields::{Cipher, CompressionType, KdfAlgorithm, KdfParams};
pub(crate) use header_fields::{KDBX_MAGIC_NUMBER, KEEPASS_MAGIC_NUMBER};
