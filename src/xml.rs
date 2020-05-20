//! Inner XML format and decrypted database data

mod decoders;
pub(crate) mod parse;
pub(crate) mod serialize;

pub use parse::parse_xml;
pub use serialize::write_xml;
