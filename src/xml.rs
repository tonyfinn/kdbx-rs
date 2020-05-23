//! Inner XML format and decrypted database data

mod decoders;
pub(crate) mod parse;
pub(crate) mod serialize;

pub use crate::stream::random::{default_stream_cipher, default_stream_cipher_with_key, InnerStreamError};
pub use parse::parse_xml;
pub use serialize::write_xml;
