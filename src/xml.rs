//! Work directly with the KDBX decrypted inner XML format

mod decoders;
pub(crate) mod parse;
pub(crate) mod serialize;

pub use crate::stream::random::InnerStreamError;
pub use decoders::{decode_datetime, decode_uuid, encode_datetime, encode_uuid};
pub use parse::parse_xml;
pub use serialize::write_xml;
