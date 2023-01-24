//! Utilities to help working with kdbx-rs

use std::fmt::Write;
use std::io;
use uuid::Uuid;

use crate::binary::KdfAlgorithm;

pub(crate) fn value_from_uuid_table<T: Clone>(
    table: &[(&str, T)],
    lookup: uuid::Uuid,
) -> Option<T> {
    for (uuid_str, ref value) in table.iter() {
        let item_uuid = Uuid::parse_str(uuid_str).ok()?;
        if item_uuid == lookup {
            return Some(value.clone());
        }
    }
    None
}

pub(crate) fn uuid_from_uuid_table<T: Clone + PartialEq>(
    table: &[(&str, T)],
    lookup: T,
) -> Option<uuid::Uuid> {
    for (uuid_str, ref value) in table.iter() {
        let item_uuid = Uuid::parse_str(uuid_str).ok()?;
        if value.clone() == lookup {
            return Some(item_uuid);
        }
    }
    None
}

pub(crate) fn buffer(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    v.resize_with(len, Default::default);
    v
}

pub(crate) struct CachingReader<'a, I>
where
    I: io::Read,
{
    data: Vec<u8>,
    inner: &'a mut I,
}

impl<'a, I: io::Read> io::Read for CachingReader<'a, I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.read(buf)?;
        self.data.extend(buf.iter().cloned());
        Ok(size)
    }
}

impl<'a, I: io::Read> CachingReader<'a, I> {
    pub(crate) fn new(inner: &'a mut I) -> CachingReader<'a, I> {
        CachingReader {
            data: Vec::new(),
            inner,
        }
    }

    pub(crate) fn into_inner(self) -> (Vec<u8>, &'a mut I) {
        (self.data, self.inner)
    }
}

#[allow(dead_code)]
/// Useful debugging method to convert a byte array to a hex string
/// e.g. [0xf2, 0xa2, 0x12] => "f2a212"
pub(crate) fn to_hex_string(data: &[u8]) -> String {
    let mut output = String::new();

    for byte in data {
        write!(output, "{:x}", byte).unwrap();
    }

    output
}

/// No-op stream cipher that does no encryption or decryption
pub struct NullStreamCipher;

impl cipher::StreamCipher for NullStreamCipher {
    fn try_apply_keystream_inout(
        &mut self,
        _buf: cipher::inout::InOutBuf<'_, '_, u8>,
    ) -> Result<(), cipher::StreamCipherError> {
        Ok(())
    }
}

/// Convert one of the Argon2 [`KdfAlgorithm`] into its [`Variant`](argon2::Variant).
/// Only Argon2d and Argon2id must be passed to this function.
pub(crate) fn argon2_algo_to_variant(algo: KdfAlgorithm) -> argon2::Variant {
    match algo {
        KdfAlgorithm::Argon2d => argon2::Variant::Argon2d,
        KdfAlgorithm::Argon2id => argon2::Variant::Argon2id,
        a => panic!("invalid algorithm {:?}", a),
    }
}

/// Convert a Argon2 [`Variant`](argon2::Variant) into the corresponding
/// [`KdfAlgorithm`]. Only Argon2d and Argon2id algorithms are supported.
pub(crate) fn argon2_variant_to_algo(variant: argon2::Variant) -> KdfAlgorithm {
   match variant {
    argon2::Variant::Argon2d => KdfAlgorithm::Argon2d,
    argon2::Variant::Argon2id => KdfAlgorithm::Argon2id,
    v => panic!("invalid variant {:?}", v),
   } 
}
