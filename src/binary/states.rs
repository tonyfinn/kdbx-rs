use super::{errors, header};
use crate::{crypto, stream};
use std::io::Read;

pub trait DatabaseState: std::fmt::Debug {
    fn header(&self) -> &header::KdbxHeader;
}

#[derive(Debug)]
/// A kdbx database
///
/// Most methods are available on a specific state
/// like KdbxDatabase<Locked> or KdbxDatase<Unlocked>
pub struct KdbxDatabase<S>
where
    S: DatabaseState,
{
    pub(super) state: S,
}

impl<T: DatabaseState> KdbxDatabase<T> {
    /// Unencrypted database configuration and custom data
    pub fn header(&self) -> &header::KdbxHeader {
        &self.state.header()
    }
}

#[derive(Debug)]
/// An unlocked database, allowing access to stored credentials
pub struct Unlocked {
    /// Header data of the kdbx archive, includes unencrypted metadata
    pub(crate) header: header::KdbxHeader,
    /// Inner header data that is stored encrypted, not present on kdbx3
    pub(crate) inner_header: Option<header::KdbxInnerHeader>,
    /// Major version of the database file format
    pub(crate) major_version: u16,
    /// Minor version of the database file format
    pub(crate) minor_version: u16,
    /// Unencrypted unparsed XML data
    pub(crate) xml_data: Vec<u8>,
}

impl DatabaseState for Unlocked {
    fn header(&self) -> &header::KdbxHeader {
        &self.header
    }
}

impl KdbxDatabase<Unlocked> {
    /// Encrypted binaries and database options
    pub fn inner_header(&self) -> Option<&header::KdbxInnerHeader> {
        self.state.inner_header.as_ref()
    }

    /// Raw XML data to handle fields not supported by this plugin
    pub fn xml_data(&self) -> &[u8] {
        &self.state.xml_data
    }
}

#[derive(Debug, PartialEq, Eq)]
/// A locked database, use unlock(composite_key) to unlock
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

impl DatabaseState for Locked {
    fn header(&self) -> &header::KdbxHeader {
        &self.header
    }
}

impl KdbxDatabase<Locked> {
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

    /// Unlocks the database
    ///
    /// If unlock fails, returns the locked database along with the error
    pub fn unlock(
        self,
        key: &crypto::CompositeKey,
    ) -> Result<KdbxDatabase<Unlocked>, (errors::UnlockError, KdbxDatabase<Locked>)> {
        let master_key = match key.master_key(&self.state.header.kdf_params) {
            Ok(master_key) => master_key,
            Err(e) => return Err((errors::UnlockError::from(e), self)),
        };

        let hmac_key = master_key.hmac_key(&self.state.header.master_seed);
        let header_block_key = hmac_key.block_key(u64::MAX);

        if header_block_key.verify_header_block(&self.state.hmac, &self.state.header_data) {
            match self.decrypt_data(&master_key) {
                Ok((inner_header, data)) => Ok(KdbxDatabase {
                    state: Unlocked {
                        header: self.state.header,
                        inner_header: Some(inner_header),
                        major_version: self.state.major_version,
                        minor_version: self.state.minor_version,
                        xml_data: data,
                    },
                }),
                Err(e) => Err((e, self)),
            }
        } else {
            Err((errors::UnlockError::HmacInvalid, self))
        }
    }
}
