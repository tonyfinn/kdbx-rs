use super::{Cipher, KEEPASS_MAGIC_NUMBER, errors, header, header_fields, KDB_MAGIC_NUMBER};
use crate::{crypto, database, stream};
use std::fs::File;
use std::path::Path;
use std::io::{Read};
use std::ops::{Deref, DerefMut};

const AES_HEADER_ID: u32 = 2;
const TWOFISH_HEADER_ID: u32 = 8;

/// Unencrypted KDB archive meta info and settings
#[derive(Debug)]
pub struct KdbHeader {
    /// Cipher used to encrypt database
    pub cipher: header_fields::Cipher,
    /// Minor database version
    pub version: u32,
    /// Seed to add to master key for salting
    pub master_seed: [u8; 16],
    /// IV used for encryption
    pub encryption_iv: [u8; 16],
    /// Number of groups to expect in DB
    pub group_count: u32,
    /// Number of entries to expect in DB
    pub entry_count: u32,
    /// SHA256 hash of database
    pub contents_hash: [u8; 32],
    /// Seed used for AES key derivation from user key
    pub transform_seed: [u8; 32],
    /// Number of rounds of AES to use.
    pub key_rounds: u32,
}

impl KdbHeader {
    pub(crate) fn read<R: Read>(mut reader: R) -> Result<(KdbHeader, Vec<u8>), errors::HeaderError> {
        let mut flag_buf = [0u8; 4];
        reader.read_exact(&mut flag_buf)?;
        let flag = u32::from_le_bytes(flag_buf);
        let cipher_value = flag & 0xFFFE; // low byte is unused flag for checksum variant
        let cipher = match cipher_value {
            AES_HEADER_ID => Cipher::Aes128,
            TWOFISH_HEADER_ID => Cipher::TwoFish,
            _ => return Err(errors::HeaderError::MalformedField(super::OuterHeaderId::CipherId, format!("Unknown KDB cipher ID: {}", flag)))
        };

        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        let version = u32::from_le_bytes(version_buf);
        
        let mut master_seed = [0u8; 16];
        reader.read_exact(&mut master_seed)?;

        let mut encryption_iv  = [0u8; 16];
        reader.read_exact(&mut encryption_iv)?;

        let mut group_count_buf = [0u8; 4];
        reader.read_exact(&mut group_count_buf)?;
        let group_count = u32::from_le_bytes(group_count_buf);

        let mut entry_count_buf = [0u8; 4];
        reader.read_exact(&mut entry_count_buf)?;
        let entry_count = u32::from_le_bytes(entry_count_buf);
        
        let mut contents_hash = [0u8; 32];
        reader.read_exact(&mut contents_hash)?;
        
        let mut transform_seed = [0u8; 32];
        reader.read_exact(&mut transform_seed)?;

        let mut key_rounds_buf = [0u8; 4];
        reader.read_exact(&mut key_rounds_buf)?;
        let key_rounds = u32::from_le_bytes(key_rounds_buf);

        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        Ok((KdbHeader {
            cipher, version, master_seed, encryption_iv, group_count, entry_count, contents_hash, transform_seed, key_rounds
        }, data))
    }
}


pub trait KdbState: std::fmt::Debug {
    fn header(&self) -> &KdbHeader;
    fn header_mut(&mut self) -> &mut KdbHeader;
}

#[derive(Debug)]
/// A KeePass 1 archive wrapping a password database
///
/// Most methods are available on a specific state like `Kdb<Locked>`
/// or `Kdb<Unlocked>`.
///
/// A keepass 1 archive can be obtained in one of two ways. You may read
/// an existing archive using [`kdb::open`][open] or
/// [`kdb::from_reader`][from_reader].
///
/// You can also create a password database using [`Database`][crate::Database],
/// then turn it into a KeePass 1 archive using [`Kdb::from_database`].
pub struct Kdb<S>
where
    S: KdbState,
{
    pub(super) state: S,
}

impl<T: KdbState> Kdb<T> {
    /// Encryption configuration and unencrypted custom data
    pub fn header(&self) -> &KdbHeader {
        self.state.header()
    }

    /// Mutable encryption configuration and unencrypted custom data
    pub fn header_mut(&mut self) -> &mut KdbHeader {
        self.state.header_mut()
    }
}


/// Read a Kdb database from a given reader implementation
pub fn from_reader<R: Read>(mut reader: R) -> Result<Kdb<Locked>, errors::OpenError> {
    let mut keepass_magic_buf = [0u8; 4];
    reader.read_exact(&mut keepass_magic_buf)?;
    if u32::from_le_bytes(keepass_magic_buf) != KEEPASS_MAGIC_NUMBER {
        return Err(errors::OpenError::NonKeepassFormat)
    }
    reader.read_exact(&mut keepass_magic_buf)?;
    if u32::from_le_bytes(keepass_magic_buf) != KDB_MAGIC_NUMBER {
        return Err(errors::OpenError::UnsupportedFileFormat)
    }
    let (header, data) = KdbHeader::read(reader)?;
    Ok(Kdb {
        state: Locked {
            header, 
            data
        }
    })
}

/// Read a database from a given path
///
/// The database starts locked, use [`Kdb::unlock`] to unlock
pub fn open<P: AsRef<Path>>(path: P) -> Result<Kdb<Locked>, errors::OpenError> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    from_reader(&mut file)
}


/// Locked keepass 1 database. 
///
/// Can be unlocked with [`Kdb::unlock`].
#[derive(Debug)]
pub struct Locked {
    header: KdbHeader,
    data: Vec<u8>
}

impl KdbState for Locked {
    fn header(&self) -> &KdbHeader {
        &self.header
    }

    fn header_mut(&mut self) -> &mut KdbHeader {
        &mut self.header
    }
}

/// Represents a failed attempt at unlocking a database
///
/// Includes the locked database and the reason the unlock failed.
/// This allows you to keep the database for interactive user and
/// e.g. promt the user for a new password if the error is key related
///
/// However, for unscripted use, `FailedUnlock` implements
/// `Into<[kdbx_rs::Error]>` and `Into<[kdbx_rs::errors::UnlockError]>`
/// for easy use with the `?` operatior.
pub struct FailedUnlock(pub Kdb<Locked>, pub errors::UnlockError);


impl From<FailedUnlock> for errors::UnlockError {
    fn from(funlock: FailedUnlock) -> errors::UnlockError {
        funlock.1
    }
}

impl Kdb<Locked> {
    /// Unlock a keepass database to access database records
    pub fn unlock(self) -> Result<Kdb<Unlocked>, FailedUnlock> {
        Err(FailedUnlock(self, errors::UnlockError::StartBytesInvalid))
    }
}

/// Unlocked keepass 1 database
#[derive(Debug)]
pub struct Unlocked {
    header: KdbHeader,
    database: crate::Database
}

impl KdbState for Unlocked {
    fn header(&self) -> &KdbHeader {
        &self.header
    }

    fn header_mut(&mut self) -> &mut KdbHeader {
        &mut self.header
    }
}

impl Deref for Kdb<Unlocked> {
    type Target = database::Database;

    fn deref(&self) -> &database::Database {
        &self.state.database
    }
}

impl DerefMut for Kdb<Unlocked> {
    fn deref_mut(&mut self) -> &mut database::Database {
        &mut self.state.database
    }
}
