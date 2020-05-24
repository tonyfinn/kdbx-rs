use super::{errors, header, Kdbx, Locked};
use crate::utils;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Read a database from a input stream
///
/// The database starts locked, use [`KdbxDatabase.unlock`] to unlock
///
/// [`KdbxDatabase.unlock`]: ./struct.KdbxDatabase.html#method.unlock
pub fn from_reader<R: Read>(mut input: R) -> Result<Kdbx<Locked>, errors::OpenError> {
    let mut caching_reader = utils::CachingReader::new(&mut input);
    let mut buffer = [0u8; 4];
    caching_reader.read_exact(&mut buffer)?;

    if u32::from_le_bytes(buffer) != super::KEEPASS_MAGIC_NUMBER {
        return Err(errors::OpenError::NonKeepassFormat);
    }

    caching_reader.read_exact(&mut buffer)?;

    if u32::from_le_bytes(buffer) != super::KDBX_MAGIC_NUMBER {
        return Err(errors::OpenError::UnsupportedFileFormat);
    }

    caching_reader.read_exact(&mut buffer)?;

    let minor_version = u16::from_le_bytes([buffer[0], buffer[1]]);
    let major_version = u16::from_le_bytes([buffer[2], buffer[3]]);

    if major_version < 3 || major_version > 4 {
        return Err(errors::OpenError::UnsupportedMajorVersion(major_version));
    }

    let (header, header_data) = header::KdbxHeader::read(caching_reader, major_version)?;
    let hmac = if major_version >= 4 {
        let mut hmac = utils::buffer(Sha256::output_size());
        input.read_exact(&mut hmac)?;
        Some(hmac)
    } else {
        None
    };
    let mut encrypted_data = Vec::new();
    input.read_to_end(&mut encrypted_data)?;

    let state = Locked {
        header,
        header_data,
        major_version,
        minor_version,
        hmac,
        encrypted_data,
    };

    Ok(Kdbx { state })
}

/// Read a database from a given path
///
/// The database starts locked, use [`KdbxDatabase.unlock`] to unlock
///
/// [`KdbxDatabase.unlock`]: ./struct.KdbxDatabase.html#method.unlock
pub fn open<P: AsRef<Path>>(path: P) -> Result<Kdbx<Locked>, errors::OpenError> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    from_reader(&mut file)
}
