//! .kdbx files and the outer binary format

pub(crate) mod errors;
mod header;
mod read;
mod states;
mod variant_dict;
mod wrapper_fields;

pub use header::{InnerHeaderId, KdbxHeader, KdbxInnerHeader, OuterHeaderId};
pub use read::{from_reader, open};
pub use states::{Kdbx, Locked, Unlocked, FailedUnlock};
pub use variant_dict::{Value as VariantDictValue, VariantDict, VariantParseError};
pub use wrapper_fields::{Cipher, CompressionType, KdfAlgorithm, KdfParams};
pub(crate) use wrapper_fields::{KDBX_MAGIC_NUMBER, KEEPASS_MAGIC_NUMBER};
