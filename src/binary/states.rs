use super::{errors, header};
use crate::{crypto, stream, types};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

pub trait KdbxState: std::fmt::Debug {
    fn header(&self) -> &header::KdbxHeader;
    fn write<W: Write>(&self, output: W) -> Result<(), errors::WriteError>;
}

#[derive(Debug)]
/// A kdbx file
///
/// Most methods are available on a specific state
/// like Kdbx<Locked> or Kdbx<Unlocked>
pub struct Kdbx<S>
where
    S: KdbxState,
{
    pub(super) state: S,
}

impl<T: KdbxState> Kdbx<T> {
    /// Unencrypted database configuration and custom data
    pub fn header(&self) -> &header::KdbxHeader {
        &self.state.header()
    }

    /// Write this database to the given output stream
    pub fn write<W: Write>(&self, output: W) -> Result<(), errors::WriteError> {
        self.state.write(output)?;
        Ok(())
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

        crate::xml::write_xml(&mut encrypted_stream, &self.database)?;

        encrypted_stream.finish()?;
        Ok(encrypted_buf)
    }
}

impl KdbxState for Unlocked {
    fn header(&self) -> &header::KdbxHeader {
        &self.header
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
            .calculate_header_hmac(&header_buf);
        output.write_all(&hmac.code())?;
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

    /// Generate a new .kdbx from the given database
    ///
    /// Uses OS randomness provided by [`getrandom`] to generate all required seed
    /// and IVs.
    ///
    /// Note that you need to set a key with [`Kdbx::set_key`]
    /// to be able to write the database
    pub fn from_database(
        database: crate::Database,
    ) -> Result<Kdbx<Unlocked>, errors::DatabaseCreationError> {
        let header = header::KdbxHeader::from_os_random()?;
        let inner_header = header::KdbxInnerHeader::from_os_random()?;
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
        Ok(Kdbx { state: unlocked })
    }
}

impl Deref for Kdbx<Unlocked> {
    type Target = types::Database;

    fn deref(&self) -> &types::Database {
        &self.state.database
    }
}

impl DerefMut for Kdbx<Unlocked> {
    fn deref_mut(&mut self) -> &mut types::Database {
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
    pub(crate) hmac: Vec<u8>,
    /// Encrypted vault data
    pub(crate) encrypted_data: Vec<u8>,
}

impl KdbxState for Locked {
    fn header(&self) -> &header::KdbxHeader {
        &self.header
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
        output.write_all(&crypto::sha256(&header_buf))?;
        output.write_all(&self.hmac)?;
        output.write_all(&self.encrypted_data)?;
        Ok(())
    }
}

impl Kdbx<Locked> {
    fn decrypt_data(
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
        let inner_header = header::KdbxInnerHeader::read(&mut input_stream)?;
        let mut output_buffer = Vec::new();
        input_stream.read_to_end(&mut output_buffer)?;
        Ok((inner_header, output_buffer))
    }

    /// Unlocks the kdbx file
    ///
    /// If unlock fails, returns the locked kdbx file along with the error
    pub fn unlock(
        self,
        key: &crypto::CompositeKey,
    ) -> Result<Kdbx<Unlocked>, (errors::UnlockError, Kdbx<Locked>)> {
        let composed_key = key.composed();
        let master_key = match composed_key.master_key(&self.state.header.kdf_params) {
            Ok(master_key) => master_key,
            Err(e) => return Err((errors::UnlockError::from(e), self)),
        };

        let hmac_key = master_key.hmac_key(&self.state.header.master_seed);
        let header_block_key = hmac_key.block_key(u64::MAX);

        if header_block_key.verify_header_block(&self.state.hmac, &self.state.header_data) {
            let parsed = self
                .decrypt_data(&master_key)
                .and_then(|(inner_header, data)| {
                    let parsed = crate::xml::parse_xml(data.as_slice())?;
                    Ok((inner_header, data, parsed))
                });

            match parsed {
                Ok((inner_header, data, db)) => Ok(Kdbx {
                    state: Unlocked {
                        header: self.state.header,
                        inner_header: inner_header,
                        major_version: self.state.major_version,
                        minor_version: self.state.minor_version,
                        composed_key: Some(composed_key),
                        master_key: Some(master_key),
                        database: db,
                        xml_data: Some(data),
                    },
                }),
                Err(e) => Err((e, self)),
            }
        } else {
            Err((errors::UnlockError::HmacInvalid, self))
        }
    }
}
