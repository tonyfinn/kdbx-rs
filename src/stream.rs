use crate::binary;
use crate::crypto;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::{Aes128, Aes256};
use block_modes::block_padding::{Padding, Pkcs7};
use block_modes::{BlockMode, Cbc};
use std::io;
use thiserror::Error;

pub const HMAC_WRITE_BLOCK_SIZE: usize = 1024 * 1024;

pub(crate) struct HMacReader<R>
where
    R: io::Read,
{
    block_idx: u64,
    buf_idx: usize,
    buffer: Vec<u8>,
    inner: R,
    hmac_key: crypto::HmacKey,
}

impl<R: io::Read> HMacReader<R> {
    pub(crate) fn new(inner: R, hmac_key: crypto::HmacKey) -> HMacReader<R> {
        HMacReader {
            block_idx: 0,
            buf_idx: 0,
            buffer: Vec::new(),
            inner,
            hmac_key,
        }
    }

    fn buffer_next_block(&mut self) -> io::Result<usize> {
        let mut hmac = [0u8; 32];
        self.inner.read_exact(&mut hmac)?;
        let mut len_buffer = [0u8; 4];
        self.inner.read_exact(&mut len_buffer)?;
        let len = u32::from_le_bytes(len_buffer) as usize;
        self.buffer.resize_with(len, Default::default);
        self.inner.read_exact(&mut self.buffer)?;
        if !self
            .hmac_key
            .block_key(self.block_idx)
            .verify_data_block(&hmac, &self.buffer)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HMAC validation failed for block {}", self.block_idx),
            ));
        }
        self.buf_idx = 0;
        self.block_idx += 1;
        Ok(len)
    }
}

impl<R: io::Read> io::Read for HMacReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut remaining_in_buffer = self.buffer.len() - self.buf_idx;

        if remaining_in_buffer == 0 {
            remaining_in_buffer = self.buffer_next_block()?;
        }
        let copy_len = usize::min(remaining_in_buffer, buf.len());
        for i in 0..copy_len {
            buf[i] = self.buffer[self.buf_idx + i];
        }
        self.buf_idx += copy_len;
        Ok(copy_len)
    }
}

pub(crate) struct HmacWriter<W>
where
    W: io::Write,
{
    block_idx: u64,
    buffer: Vec<u8>,
    inner: W,
    hmac_key: crypto::HmacKey,
}

impl<W: io::Write> HmacWriter<W> {
    pub(crate) fn new(inner: W, hmac_key: crypto::HmacKey) -> HmacWriter<W> {
        HmacWriter {
            block_idx: 0,
            buffer: Vec::with_capacity(HMAC_WRITE_BLOCK_SIZE),
            inner,
            hmac_key,
        }
    }

    fn write_block(&mut self) -> io::Result<()> {
        let hmac = self
            .hmac_key
            .block_key(self.block_idx)
            .calculate_data_hmac(&self.buffer);
        self.inner.write_all(&hmac.code())?;
        self.inner
            .write_all(&(self.buffer.len() as u32).to_le_bytes())?;
        self.inner.write_all(&self.buffer)?;
        self.block_idx += 1;
        Ok(())
    }
}

impl<W: io::Write> io::Write for HmacWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let space_in_buffer = HMAC_WRITE_BLOCK_SIZE - self.buffer.len();
        let write_size = usize::min(buf.len(), space_in_buffer);
        self.buffer.extend_from_slice(&buf[0..write_size]);
        if write_size < buf.len() {
            // Internal buffer full, write it out
            self.write_block()?;
            self.buffer.clear();
        }
        Ok(write_size)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_block()?;
        self.inner.flush()?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub(crate) enum BlockCipherError {
    #[error("Invalid length for IV")]
    InvalidIvLength(#[from] block_modes::InvalidKeyIvLength),
}

pub(crate) struct BlockCipherReader<C, R>
where
    R: io::Read,
    C: BlockCipher,
{
    inner: R,
    buffer: GenericArray<u8, C::BlockSize>,
    buf_idx: usize,
    cipher: Cbc<C, Pkcs7>,
    first_read: bool,
    peek_byte: Option<u8>,
}

impl<C, R> BlockCipherReader<C, R>
where
    R: io::Read,
    C: BlockCipher,
{
    pub(crate) fn wrap(
        inner: R,
        key: crypto::CipherKey,
        iv: &[u8],
    ) -> Result<BlockCipherReader<C, R>, BlockCipherError> {
        Ok(BlockCipherReader {
            inner,
            cipher: Cbc::new_var(&key.0, &iv)?,
            buffer: GenericArray::default(),
            buf_idx: 0,
            first_read: true,
            peek_byte: None,
        })
    }

    fn buffer_next_block(&mut self) -> io::Result<usize> {
        self.buf_idx = 0;
        let mut buffered_bytes = 0;

        if let Some(byte) = self.peek_byte {
            self.buffer[0] = byte;
            buffered_bytes = 1;
        } else if !self.first_read {
            return Ok(0);
        }
        self.first_read = false;
        while buffered_bytes < self.buffer.len() {
            let count = self.inner.read(&mut self.buffer[buffered_bytes..])?;
            if count == 0 && buffered_bytes != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Data size not a multiple of block size, {} extra bytes",
                        count
                    ),
                ));
            } else if count == 0 {
                return Ok(0);
            }
            buffered_bytes += count
        }

        let mut peek_buf = [0u8];
        let peek_len = self.inner.read(&mut peek_buf)?;
        self.peek_byte = if peek_len > 0 {
            Some(peek_buf[0])
        } else {
            None
        };

        let mut blocks_to_decrypt = [std::mem::take(&mut self.buffer)];
        self.cipher.decrypt_blocks(&mut blocks_to_decrypt);

        let [decrypted_block] = blocks_to_decrypt;
        self.buffer = decrypted_block;

        if self.peek_byte.is_none() {
            let unpadded = Pkcs7::unpad(&self.buffer)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Bad padding"))?;
            Ok(unpadded.len())
        } else {
            Ok(buffered_bytes)
        }
    }
}

impl<C, R> io::Read for BlockCipherReader<C, R>
where
    R: io::Read,
    C: BlockCipher,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut remaining_in_buffer = self.buffer.len() - self.buf_idx;

        if remaining_in_buffer == 0 || self.first_read {
            remaining_in_buffer = self.buffer_next_block()?;
        }
        let copy_len = usize::min(remaining_in_buffer, buf.len());
        for i in 0..copy_len {
            buf[i] = self.buffer[self.buf_idx + i];
        }
        self.buf_idx += copy_len;
        Ok(copy_len)
    }
}

pub(crate) struct BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher,
{
    inner: W,
    buffer: GenericArray<u8, C::BlockSize>,
    buf_idx: usize,
    cipher: Cbc<C, Pkcs7>,
}

impl<C, W> BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher,
{
    pub(crate) fn wrap(
        inner: W,
        key: crypto::CipherKey,
        iv: &[u8],
    ) -> Result<BlockCipherWriter<C, W>, BlockCipherError> {
        Ok(BlockCipherWriter {
            inner,
            cipher: Cbc::new_var(&key.0, &iv)?,
            buffer: GenericArray::default(),
            buf_idx: 0,
        })
    }

    fn write_buffer(&mut self) -> io::Result<()> {
        let mut blocks_to_encrypt = [std::mem::take(&mut self.buffer)];
        self.cipher.encrypt_blocks(&mut blocks_to_encrypt);
        self.inner.write_all(&blocks_to_encrypt[0])?;
        Ok(())
    }
}

impl<C, W> io::Write for BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for byte in buf.iter() {
            self.buffer[self.buf_idx] = *byte;
            self.buf_idx += 1;
            if self.buf_idx == self.buffer.len() {
                self.write_buffer()?;
                self.buf_idx = 0;
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<C, W> Drop for BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher,
{
    fn drop(&mut self) {
        Pkcs7::pad_block(&mut self.buffer, self.buf_idx).unwrap();
        if let Err(e) = self.write_buffer() {
            println!(
                "Error finalising database write {}! Likely database corruption!",
                e
            )
        };
    }
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
        binary::Cipher::Aes256 => BlockCipherReader::<Aes256, _>::wrap(verified, cipher_key, iv)
            .map(|r| Box::new(r) as Box<dyn io::Read>)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid cipher params - Could not create CBC block mode".to_string(),
                )
            }),
        binary::Cipher::Aes128 => BlockCipherReader::<Aes128, _>::wrap(verified, cipher_key, iv)
            .map(|r| Box::new(r) as Box<dyn io::Read>)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid cipher params - Could not create CBC block mode".to_string(),
                )
            }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported cipher setting {:?}", cipher),
        )),
    }?;
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

pub(crate) fn kdbx4_write_stream<'a, W: io::Write + 'a>(
    inner: W,
    hmac_key: crypto::HmacKey,
    cipher_key: crypto::CipherKey,
    cipher: binary::Cipher,
    iv: &[u8],
    compression: binary::CompressionType,
) -> io::Result<Box<dyn io::Write + 'a>> {
    let buffered = io::BufWriter::new(inner);
    let verified = HmacWriter::new(buffered, hmac_key);
    let encrypted: Box<dyn io::Write> = match cipher {
        binary::Cipher::Aes256 => BlockCipherWriter::<Aes256, _>::wrap(verified, cipher_key, iv)
            .map(|w| Box::new(w) as Box<dyn io::Write>)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid cipher params - Could not create CBC block mode".to_string(),
                )
            }),
        binary::Cipher::Aes128 => BlockCipherWriter::<Aes128, _>::wrap(verified, cipher_key, iv)
            .map(|w| Box::new(w) as Box<dyn io::Write>)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid cipher params - Could not create CBC block mode".to_string(),
                )
            }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported cipher setting {:?}", cipher),
        )),
    }?;
    let compressed: Box<dyn io::Write> = match compression {
        binary::CompressionType::None => Box::new(encrypted),
        binary::CompressionType::Gzip => Box::new(libflate::gzip::Encoder::new(encrypted)?),
        binary::CompressionType::Unknown(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported compression type {:?}", compression),
            ))
        }
    };

    Ok(compressed)
}
