use super::{errors, header};
use crate::{crypto, database, stream};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

pub trait KdbxState: std::fmt::Debug {
    fn header(&self) -> &header::KdbxHeader;
    fn header_mut(&mut self) -> &mut header::KdbxHeader;
    fn major_version(&self) -> u16;
    fn minor_version(&self) -> u16;
    fn write<W: Write>(&self, output: W) -> Result<(), errors::WriteError>;
}

#[derive(Debug)]
/// A KeePass 2 archive wrapping a password database
///
/// Most methods are available on a specific state like `Kdbx<Locked>`
/// or `Kdbx<Unlocked>`.
///
/// A keepass 2 archive can be obtained in one of two ways. You may read
/// an existing archive using [`kdbx_rs::open`][crate::open] or
/// [`kdbx_rs::from_reader`][crate::from_reader].
///
/// You can also create a password database using [`Database`][crate::Database],
/// then turn it into a KeePass 2 archive using [`Kdbx::from_database`].
pub struct Kdbx<S>
where
    S: KdbxState,
{
    pub(super) state: S,
}

impl<T: KdbxState> Kdbx<T> {
    /// Encryption configuration and unencrypted custom data
    pub fn header(&self) -> &header::KdbxHeader {
        self.state.header()
    }

    /// Mutable encryption configuration and unencrypted custom data
    pub fn header_mut(&mut self) -> &mut header::KdbxHeader {
        self.state.header_mut()
    }

    /// Major archive version
    pub fn major_version(&self) -> u16 {
        self.state.major_version()
    }

    /// Major archive version
    pub fn minor_version(&self) -> u16 {
        self.state.minor_version()
    }

    /// Write this archive to the given output stream
    pub fn write<W: Write>(&self, output: W) -> Result<(), errors::WriteError> {
        self.state.write(output)?;
        Ok(())
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
pub struct FailedUnlock(pub Kdbx<Locked>, pub errors::UnlockError);

impl From<FailedUnlock> for errors::UnlockError {
    fn from(funlock: FailedUnlock) -> errors::UnlockError {
        funlock.1
    }
}

#[derive(Debug)]
/// An unlocked kdbx file, allowing access to stored credentials
pub struct Unlocked {
    /// Header data of the kdbx archive, includes unencrypted metadata
    pub(crate) header: header::KdbxHeader,
    /// Inner header data that is stored encrypted, not present on kdbx3
    pub(crate) inner_header: header::KdbxInnerHeader,
    /// Major version of the database file format
    pub(crate) major_version: u16,
    /// Minor version of the database file format
    pub(crate) minor_version: u16,
    /// Master key used to derive other keys
    pub(crate) composed_key: Option<crypto::ComposedKey>,
    /// Master key used to derive other keys
    pub(crate) master_key: Option<crypto::MasterKey>,
    /// Unencrypted unparsed XML data
    pub(crate) xml_data: Option<Vec<u8>>,
    /// Actual password database data
    pub(crate) database: crate::Database,
}

impl Unlocked {
    fn encrypt_inner(&self, key: &crypto::MasterKey) -> Result<Vec<u8>, super::errors::WriteError> {
        let mut encrypted_buf = Vec::new();
        let mut encrypted_stream = crate::stream::kdbx4_write_stream(
            &mut encrypted_buf,
            key.hmac_key(&self.header.master_seed),
            key.cipher_key(&self.header.master_seed),
            self.header.cipher,
            &self.header.encryption_iv,
            self.header.compression_type,
        )?;
        self.inner_header.write(&mut encrypted_stream)?;
        let mut stream_cipher = self
            .inner_header
            .inner_stream_cipher
            .stream_cipher(&self.inner_header.inner_stream_key)?;
        crate::xml::write_xml(
            &mut encrypted_stream,
            &self.database,
            stream_cipher.as_mut(),
        )?;

        encrypted_stream.finish()?;
        Ok(encrypted_buf)
    }
}

impl KdbxState for Unlocked {
    fn header(&self) -> &header::KdbxHeader {
        &self.header
    }

    fn header_mut(&mut self) -> &mut header::KdbxHeader {
        &mut self.header
    }

    fn major_version(&self) -> u16 {
        self.major_version
    }

    fn minor_version(&self) -> u16 {
        self.minor_version
    }

    fn write<W: Write>(&self, mut output: W) -> Result<(), errors::WriteError> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or(errors::WriteError::MissingKeys)?;
        let mut header_buf = Vec::new();
        let header_writer = &mut header_buf as &mut dyn Write;
        header_writer.write_all(&super::KEEPASS_MAGIC_NUMBER.to_le_bytes())?;
        header_writer.write_all(&super::KDBX_MAGIC_NUMBER.to_le_bytes())?;
        header_writer.write_all(&self.minor_version.to_le_bytes())?;
        header_writer.write_all(&self.major_version.to_le_bytes())?;
        self.header.write(&mut header_buf)?;
        output.write_all(&header_buf)?;
        output.write_all(&crypto::sha256(&header_buf))?;
        let hmac_key = master_key.hmac_key(&self.header.master_seed);
        let hmac = hmac_key
            .block_key(u64::MAX)
            .calculate_header_hmac(&header_buf)
            .map_err(|_| errors::WriteError::MissingKeys)?;
        output.write_all(&hmac.into_bytes())?;
        let encrypted_xml = self.encrypt_inner(&master_key)?;
        output.write_all(&encrypted_xml)?;
        Ok(())
    }
}

impl Kdbx<Unlocked> {
    /// Encrypted binaries and database options
    pub fn inner_header(&self) -> &header::KdbxInnerHeader {
        &self.state.inner_header
    }

    /// Mutable encrypted binaries and database options
    pub fn inner_header_mut(&mut self) -> &mut header::KdbxInnerHeader {
        &mut self.state.inner_header
    }

    /// Use the given composite key to encrypt the database
    pub fn set_key(
        &mut self,
        key: crypto::CompositeKey,
    ) -> Result<(), crate::errors::KeyGenerationError> {
        self.state.composed_key = Some(key.composed());
        let composed_key = self.state.composed_key.as_ref().unwrap();
        self.state.master_key = Some(composed_key.master_key(&self.header().kdf_params)?);

        Ok(())
    }

    /// Raw parsed XML data to handle fields not supported by this plugin
    ///
    /// Only present from databases loaded from existing sources
    pub fn raw_xml(&self) -> Option<&[u8]> {
        self.state.xml_data.as_deref()
    }

    /// Password database stored in this kdbx archive
    pub fn database(&self) -> &crate::Database {
        &self.state.database
    }

    /// Mutable password database stored in this kdbx archive
    pub fn database_mut(&mut self) -> &mut crate::Database {
        &mut self.state.database
    }

    /// Generate a new .kdbx from the given database
    ///
    /// Uses OS randomness provided by the `rand` crates's [`OsRng`] to
    /// generate all required seeds and IVs.
    ///
    /// Note that you need to set a key with [`Kdbx::set_key`]
    /// to be able to write the database
    ///
    /// [`OsRng`]: https://docs.rs/rand/0.7/rand/rngs/struct.OsRng.html
    pub fn from_database(database: crate::Database) -> Kdbx<Unlocked> {
        let header = header::KdbxHeader::from_os_random();
        let inner_header = header::KdbxInnerHeader::from_os_random();
        let unlocked = Unlocked {
            header,
            inner_header,
            major_version: 4,
            minor_version: 0,
            xml_data: None,
            composed_key: None,
            master_key: None,
            database,
        };
        Kdbx { state: unlocked }
    }
}

impl Deref for Kdbx<Unlocked> {
    type Target = database::Database;

    fn deref(&self) -> &database::Database {
        &self.state.database
    }
}

impl DerefMut for Kdbx<Unlocked> {
    fn deref_mut(&mut self) -> &mut database::Database {
        &mut self.state.database
    }
}

#[derive(Debug, PartialEq, Eq)]
/// A locked kdbx file, use unlock(composite_key) to unlock
pub struct Locked {
    /// Header data of the kdbx archive, includes unencrypted metadata
    pub(crate) header: header::KdbxHeader,
    /// Raw bytes of header data, useful for checksums
    pub(crate) header_data: Vec<u8>,
    /// Major version of the database file format
    pub(crate) major_version: u16,
    /// Minor version of the database file format
    pub(crate) minor_version: u16,
    /// hmac code to verify keys and header integrity
    pub(crate) hmac: Option<Vec<u8>>,
    /// Encrypted vault data
    pub(crate) encrypted_data: Vec<u8>,
}

impl KdbxState for Locked {
    fn header(&self) -> &header::KdbxHeader {
        &self.header
    }

    fn header_mut(&mut self) -> &mut header::KdbxHeader {
        &mut self.header
    }

    fn major_version(&self) -> u16 {
        self.major_version
    }

    fn minor_version(&self) -> u16 {
        self.minor_version
    }

    fn write<W: Write>(&self, mut output: W) -> Result<(), errors::WriteError> {
        let mut header_buf = Vec::new();
        let header_writer = &mut header_buf as &mut dyn Write;
        header_writer.write_all(&super::KEEPASS_MAGIC_NUMBER.to_le_bytes())?;
        header_writer.write_all(&super::KDBX_MAGIC_NUMBER.to_le_bytes())?;
        header_writer.write_all(&self.minor_version.to_le_bytes())?;
        header_writer.write_all(&self.major_version.to_le_bytes())?;
        self.header.write(&mut header_buf)?;
        output.write_all(&header_buf)?;
        if self.major_version >= 4 {
            output.write_all(&crypto::sha256(&header_buf))?;
            output.write_all(&self.hmac.as_ref().unwrap())?;
        }
        output.write_all(&self.encrypted_data)?;
        Ok(())
    }
}

impl Kdbx<Locked> {
    fn decrypt_v4(
        &self,
        master_key: &crypto::MasterKey,
    ) -> Result<(header::KdbxInnerHeader, Vec<u8>), errors::UnlockError> {
        let hmac_key = master_key.hmac_key(&self.state.header.master_seed);
        let cipher_key = master_key.cipher_key(&self.state.header.master_seed);
        let mut input_stream = stream::kdbx4_read_stream(
            &*self.state.encrypted_data,
            hmac_key,
            cipher_key,
            self.state.header.cipher,
            &self.state.header.encryption_iv,
            self.state.header.compression_type,
        )?;
        let inner_header =
            header::KdbxInnerHeader::read(&mut input_stream, self.state.major_version)?;
        let mut output_buffer = Vec::new();
        input_stream.read_to_end(&mut output_buffer)?;
        Ok((inner_header, output_buffer))
    }

    /// Unlocks the kdbx file
    ///
    /// If unlock fails, returns the locked kdbx file along with the error
    pub fn unlock(self, key: &crypto::CompositeKey) -> Result<Kdbx<Unlocked>, FailedUnlock> {
        if self.state.major_version >= 4 {
            self.unlock_v4(&key)
        } else {
            self.unlock_v3(&key)
        }
    }

    fn decrypt_v3(
        &self,
        master_key: &crypto::MasterKey,
    ) -> Result<(header::KdbxInnerHeader, Vec<u8>), errors::UnlockError> {
        let cipher_key = master_key.cipher_key(&self.state.header.master_seed);
        let mut input_stream = stream::kdbx3_read_stream(
            &*self.state.encrypted_data,
            cipher_key,
            self.state.header.cipher,
            &self.state.header.encryption_iv,
            self.state.header.compression_type,
            self.header().stream_start_bytes.as_ref().unwrap(),
        )?;
        let inner_header = header::KdbxInnerHeader::from_legacy_fields(&self.state.header)?;
        let mut output_buffer = Vec::new();
        input_stream.read_to_end(&mut output_buffer)?;
        Ok((inner_header, output_buffer))
    }

    fn unlock_v3(self, key: &crypto::CompositeKey) -> Result<Kdbx<Unlocked>, FailedUnlock> {
        let composed_key = key.composed();
        let master_key = match composed_key.master_key(&self.header().kdf_params) {
            Ok(master_key) => master_key,
            Err(e) => return Err(FailedUnlock(self, errors::UnlockError::from(e))),
        };

        let parsed = self
            .decrypt_v3(&master_key)
            .and_then(|(inner_header, data)| {
                let mut stream_cipher = inner_header
                    .inner_stream_cipher
                    .stream_cipher(inner_header.inner_stream_key.as_ref())?;
                let parsed = crate::xml::parse_xml(data.as_slice(), stream_cipher.as_mut())?;
                Ok((inner_header, data, parsed))
            });
        match parsed {
            Ok((inner_header, data, db)) => Ok(Kdbx {
                state: Unlocked {
                    inner_header,
                    header: self.state.header,
                    major_version: self.state.major_version,
                    minor_version: self.state.minor_version,
                    composed_key: Some(composed_key),
                    master_key: Some(master_key),
                    database: db,
                    xml_data: Some(data),
                },
            }),
            Err(e) => Err(FailedUnlock(self, e)),
        }
    }

    fn unlock_v4(self, key: &crypto::CompositeKey) -> Result<Kdbx<Unlocked>, FailedUnlock> {
        let composed_key = key.composed();
        let master_key = match composed_key.master_key(&self.header().kdf_params) {
            Ok(master_key) => master_key,
            Err(e) => return Err(FailedUnlock(self, errors::UnlockError::from(e))),
        };
        let hmac_key = master_key.hmac_key(&self.state.header.master_seed);
        let header_block_key = hmac_key.block_key(u64::MAX);

        let hmac = self.state.hmac.clone().unwrap();

        if header_block_key.verify_header_block(hmac.as_ref(), &self.state.header_data) {
            let parsed = self
                .decrypt_v4(&master_key)
                .and_then(|(inner_header, data)| {
                    let mut stream_cipher = inner_header
                        .inner_stream_cipher
                        .stream_cipher(inner_header.inner_stream_key.as_ref())?;
                    let parsed = crate::xml::parse_xml(data.as_slice(), stream_cipher.as_mut())?;
                    Ok((inner_header, data, parsed))
                });

            match parsed {
                Ok((inner_header, data, db)) => Ok(Kdbx {
                    state: Unlocked {
                        inner_header,
                        header: self.state.header,
                        major_version: self.state.major_version,
                        minor_version: self.state.minor_version,
                        composed_key: Some(composed_key),
                        master_key: Some(master_key),
                        database: db,
                        xml_data: Some(data),
                    },
                }),
                Err(e) => Err(FailedUnlock(self, e)),
            }
        } else {
            Err(FailedUnlock(self, errors::UnlockError::HmacInvalid))
        }
    }
}
