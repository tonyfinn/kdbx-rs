use crate::binary;
use crate::crypto;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::{Aes128, Aes256};
use block_modes::block_padding::{Padding, Pkcs7};
use block_modes::{BlockMode, Cbc};
use std::io;
use thiserror::Error;

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
