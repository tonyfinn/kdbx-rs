use crate::binary;
use crate::crypto;
use std::io;

use aes::{Aes128, Aes256};
use aes::block_cipher_trait::BlockCipher;
use derive_more::From;
use twofish::Twofish;

use super::{BlockCipherReader, BlockCipherWriter, BlockCipherWriterExt, HMacReader, HmacWriter};

fn block_cipher_read_stream<C, R>(inner: R, key: crypto::CipherKey, iv: &[u8]) -> io::Result<BlockCipherReader<C, R>>
    where C: BlockCipher,
        R: io::Read
{
    BlockCipherReader::<C, _>::wrap(inner, key, iv)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid cipher params - Could not create CBC block mode".to_string(),
            )
        })
}

pub(crate) fn kdbx4_read_stream<'a, R: io::Read + 'a>(
    inner: R,
    hmac_key: crypto::HmacKey,
    cipher_key: crypto::CipherKey,
    cipher: binary::Cipher,
    iv: &[u8],
    compression: binary::CompressionType,
) -> io::Result<Box<dyn io::Read + 'a>> {
    let buffered = io::BufReader::new(inner);
    let verified = HMacReader::new(buffered, hmac_key);
    let decrypted: Box<dyn io::Read> = match cipher {
        binary::Cipher::Aes256 => {
            Box::new(block_cipher_read_stream::<Aes256, _>(verified, cipher_key, iv)?)
        },
        binary::Cipher::Aes128 => {
            Box::new(block_cipher_read_stream::<Aes128, _>(verified, cipher_key, iv)?)
        },
        binary::Cipher::TwoFish => {
            Box::new(block_cipher_read_stream::<Twofish, _>(verified, cipher_key, iv)?)
        },
        _ => return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported cipher setting {:?}", cipher),
        )),
    };
    let decompressed: Box<dyn io::Read> = match compression {
        binary::CompressionType::None => Box::new(decrypted),
        binary::CompressionType::Gzip => Box::new(libflate::gzip::Decoder::new(decrypted)?),
        binary::CompressionType::Unknown(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported compression type {:?}", compression),
            ))
        }
    };

    Ok(decompressed)
}

enum Kdbx4WriteInner<'a, W>
where
    W: 'a + io::Write,
{
    Raw(Box<dyn BlockCipherWriterExt<'a, HmacWriter<'a, W>> + 'a>),
    Gzip(libflate::gzip::Encoder<Box<dyn BlockCipherWriterExt<'a, HmacWriter<'a, W>> + 'a>>),
}

#[derive(From)]
pub struct Kdbx4Write<'a, W: 'a + io::Write>(Kdbx4WriteInner<'a, W>);

impl<'a, W> Kdbx4Write<'a, W>
where
    W: 'a + io::Write,
{
    pub(crate) fn finish(self) -> io::Result<W> {
        let mut encryption = match self.0 {
            Kdbx4WriteInner::Raw(inner) => Ok(inner),
            Kdbx4WriteInner::Gzip(gz) => gz
                .finish()
                .into_result(),
        }?;
        let hmacw = encryption.finish()?;
        let mut inner = hmacw.finish()?;
        inner.flush()?;
        Ok(inner)
    }
}

impl<'a, W> io::Write for Kdbx4Write<'a, W>
where
    W: 'a + io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0 {
            Kdbx4WriteInner::Raw(ref mut inner) => inner.write(buf),
            Kdbx4WriteInner::Gzip(ref mut inner) => inner.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.0 {
            Kdbx4WriteInner::Raw(ref mut inner) => inner.flush(),
            Kdbx4WriteInner::Gzip(ref mut inner) => inner.flush(),
        }
    }
}

pub(crate) fn block_cipher_write_stream<C, W>(inner: W, key: crypto::CipherKey, iv: &[u8]) -> io::Result<BlockCipherWriter<C, W>>
    where W: io::Write,
        C: BlockCipher
{
    BlockCipherWriter::<C, _>::wrap(inner, key, iv)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid cipher params - Could not create CBC block mode".to_string(),
            )
        })
}

pub(crate) fn kdbx4_write_stream<'a, W: 'a + io::Write>(
    inner: W,
    hmac_key: crypto::HmacKey,
    cipher_key: crypto::CipherKey,
    cipher: binary::Cipher,
    iv: &[u8],
    compression: binary::CompressionType,
) -> io::Result<Kdbx4Write<'a, W>> {
    let verified = HmacWriter::new(inner, hmac_key);
    let encrypted: Box<dyn BlockCipherWriterExt<HmacWriter<'a, W>> + 'a> = match cipher {
        binary::Cipher::Aes256 => Box::new(block_cipher_write_stream::<Aes256, _>(verified, cipher_key, iv)?),
        binary::Cipher::Aes128 => Box::new(block_cipher_write_stream::<Aes128, _>(verified, cipher_key, iv)?),
        binary::Cipher::TwoFish => Box::new(block_cipher_write_stream::<Twofish, _>(verified, cipher_key, iv)?),
        _ => return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported cipher setting {:?}", cipher),
        )),
    };
    Ok(match compression {
        binary::CompressionType::None => Kdbx4WriteInner::Raw(encrypted).into(),
        binary::CompressionType::Gzip => {
            Kdbx4WriteInner::Gzip(libflate::gzip::Encoder::new(encrypted)?).into()
        }
        binary::CompressionType::Unknown(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported compression type {:?}", compression),
            ))
        }
    })
}
