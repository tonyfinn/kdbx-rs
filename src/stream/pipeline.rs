use crate::binary;
use crate::crypto;
use std::io;

use aes::{Aes128, Aes256};
use chacha20::ChaCha20;
use cipher::BlockCipher;
use cipher::BlockDecrypt;
use cipher::BlockEncrypt;
use cipher::KeyInit;
use cipher::KeyIvInit;
use derive_more::From;
use twofish::Twofish;

use super::{
    BlockCipherReader, BlockCipherWriter, BlockCipherWriterExt, HMacReader, HashedBlockReader,
    HmacWriter, StreamCipherWriterExt,
};

fn block_cipher_read_stream<C, R>(
    inner: R,
    key: crypto::CipherKey,
    iv: &[u8],
) -> io::Result<BlockCipherReader<C, R>>
where
    C: BlockCipher + BlockDecrypt + KeyInit,
    R: io::Read,
{
    BlockCipherReader::<C, _>::wrap(inner, key, iv).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid cipher params - Could not create CBC block mode".to_string(),
        )
    })
}

pub(crate) fn decryption_stream<'a, R: io::Read + 'a>(
    inner: R,
    cipher_key: crypto::CipherKey,
    cipher: binary::Cipher,
    iv: &[u8],
) -> io::Result<Box<dyn io::Read + 'a>> {
    let stream: Box<dyn io::Read> = match cipher {
        binary::Cipher::Aes256 => Box::new(block_cipher_read_stream::<Aes256, _>(
            inner, cipher_key, iv,
        )?),
        binary::Cipher::Aes128 => Box::new(block_cipher_read_stream::<Aes128, _>(
            inner, cipher_key, iv,
        )?),
        binary::Cipher::TwoFish => Box::new(block_cipher_read_stream::<Twofish, _>(
            inner, cipher_key, iv,
        )?),
        binary::Cipher::ChaCha20 => {
            let cipher = ChaCha20::new_from_slices(&cipher_key.0, &iv).unwrap();
            Box::new(super::StreamCipherReader::new(inner, cipher))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported cipher setting {:?}", cipher),
            ))
        }
    };

    Ok(stream)
}

pub(crate) fn kdbx3_read_stream<'a, R: io::Read + 'a>(
    inner: R,
    cipher_key: crypto::CipherKey,
    cipher: binary::Cipher,
    iv: &[u8],
    compression: binary::CompressionType,
    expected_start_bytes: &[u8],
) -> io::Result<Box<dyn io::Read + 'a>> {
    let buffered = io::BufReader::new(inner);
    let mut decrypted = decryption_stream(buffered, cipher_key, cipher, iv)?;
    let mut start_bytes = [0u8; 32];
    decrypted.read_exact(&mut start_bytes)?;
    if &start_bytes != expected_start_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not validate start bytes",
        ));
    }
    let verified = HashedBlockReader::new(decrypted);
    let decompressed: Box<dyn io::Read> = match compression {
        binary::CompressionType::None => Box::new(verified),
        binary::CompressionType::Gzip => Box::new(libflate::gzip::Decoder::new(verified)?),
        binary::CompressionType::Unknown(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported compression type {:?}", compression),
            ))
        }
    };

    Ok(decompressed)
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
    let decrypted = decryption_stream(verified, cipher_key, cipher, iv)?;
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

#[derive(From)]
enum EncryptWrite<'a, W>
where
    W: 'a + io::Write,
{
    Block(Box<dyn BlockCipherWriterExt<'a, HmacWriter<'a, W>> + 'a>),
    Stream(Box<dyn StreamCipherWriterExt<HmacWriter<'a, W>> + 'a>),
}

impl<'a, W> EncryptWrite<'a, W>
where
    W: 'a + io::Write,
{
    fn finish(self) -> io::Result<HmacWriter<'a, W>> {
        match self {
            EncryptWrite::Block(mut inner) => inner.finish(),
            EncryptWrite::Stream(mut inner) => Ok(inner.into_inner()),
        }
    }
}

impl<'a, W> io::Write for EncryptWrite<'a, W>
where
    W: 'a + io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            EncryptWrite::Block(inner) => inner.write(buf),
            EncryptWrite::Stream(inner) => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            EncryptWrite::Block(inner) => inner.flush(),
            EncryptWrite::Stream(inner) => inner.flush(),
        }
    }
}

enum Kdbx4WriteInner<'a, W>
where
    W: 'a + io::Write,
{
    Raw(EncryptWrite<'a, W>),
    Gzip(libflate::gzip::Encoder<EncryptWrite<'a, W>>),
}

#[derive(From)]
pub struct Kdbx4Write<'a, W: 'a + io::Write>(Kdbx4WriteInner<'a, W>);

impl<'a, W> Kdbx4Write<'a, W>
where
    W: 'a + io::Write,
{
    pub(crate) fn finish(self) -> io::Result<W> {
        let encryption = match self.0 {
            Kdbx4WriteInner::Raw(inner) => Ok(inner),
            Kdbx4WriteInner::Gzip(gz) => gz.finish().into_result(),
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

fn block_cipher_write_stream<'a, 'b, C, W>(
    inner: HmacWriter<'a, W>,
    key: crypto::CipherKey,
    iv: &'b [u8],
) -> io::Result<EncryptWrite<'a, W>>
where
    W: io::Write,
    C: BlockCipher + BlockEncrypt + KeyInit + 'static,
{
    let writer = BlockCipherWriter::<C, _>::wrap(inner, key, iv).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid cipher params - Could not create CBC block mode".to_string(),
        )
    })?;

    Ok(EncryptWrite::Block(Box::new(writer) as Box<_>))
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
    let encrypted = match cipher {
        binary::Cipher::Aes256 => block_cipher_write_stream::<Aes256, _>(verified, cipher_key, iv)?,
        binary::Cipher::Aes128 => block_cipher_write_stream::<Aes128, _>(verified, cipher_key, iv)?,
        binary::Cipher::TwoFish => {
            block_cipher_write_stream::<Twofish, _>(verified, cipher_key, iv)?
        }
        binary::Cipher::ChaCha20 => {
            let cipher = ChaCha20::new_from_slices(&cipher_key.0, &iv).unwrap();
            EncryptWrite::Stream(Box::new(super::StreamCipherWriter::new(verified, cipher)))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported cipher setting {:?}", cipher),
            ))
        }
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
