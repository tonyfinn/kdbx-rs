use crate::crypto;
use cipher::block_padding::{Padding, Pkcs7};
use cipher::generic_array::GenericArray;
use cipher::{BlockCipher, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum BlockCipherError {
    #[error("Invalid length for IV")]
    InvalidIvLength(#[from] cipher::crypto_common::InvalidLength),
}

pub(crate) struct BlockCipherReader<C, R>
where
    R: io::Read,
    C: BlockCipher + BlockDecryptMut,
{
    inner: R,
    buffer: GenericArray<u8, C::BlockSize>,
    buf_idx: usize,
    cipher: cbc::Decryptor<C>,
    first_read: bool,
    peek_byte: Option<u8>,
}

impl<C, R> BlockCipherReader<C, R>
where
    R: io::Read,
    C: BlockCipher + BlockDecryptMut + KeyInit,
{
    pub(crate) fn wrap(
        inner: R,
        key: crypto::CipherKey,
        iv: &[u8],
    ) -> Result<BlockCipherReader<C, R>, BlockCipherError> {
        Ok(BlockCipherReader {
            inner,
            cipher: cbc::Decryptor::new_from_slices(&key.0, iv)?,
            buffer: GenericArray::default(),
            buf_idx: 0,
            first_read: true,
            peek_byte: None,
        })
    }
}

impl<C, R> BlockCipherReader<C, R>
where
    R: io::Read,
    C: BlockCipher + BlockDecryptMut,
{
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
        self.cipher.decrypt_blocks_mut(&mut blocks_to_decrypt);

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
    C: BlockCipher + BlockDecryptMut,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut remaining_in_buffer = self.buffer.len() - self.buf_idx;

        if remaining_in_buffer == 0 || self.first_read {
            remaining_in_buffer = self.buffer_next_block()?;
        }
        let copy_len = usize::min(remaining_in_buffer, buf.len());
        for (i, byte) in buf.iter_mut().enumerate().take(copy_len) {
            *byte = self.buffer[self.buf_idx + i];
        }
        self.buf_idx += copy_len;
        Ok(copy_len)
    }
}

pub trait BlockCipherWriterExt<'a, W>: io::Write
where
    W: io::Write + 'a,
{
    fn finish(&mut self) -> io::Result<W>;
}

pub(crate) struct BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher + BlockEncryptMut,
{
    inner: Option<W>,
    buffer: GenericArray<u8, C::BlockSize>,
    buf_idx: usize,
    cipher: cbc::Encryptor<C>,
}

impl<C, W> BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher + BlockEncryptMut + KeyInit,
{
    pub(crate) fn wrap(
        inner: W,
        key: crypto::CipherKey,
        iv: &[u8],
    ) -> Result<BlockCipherWriter<C, W>, BlockCipherError> {
        Ok(BlockCipherWriter {
            inner: Some(inner),
            cipher: cbc::Encryptor::new_from_slices(&key.0, iv)?,
            buffer: GenericArray::default(),
            buf_idx: 0,
        })
    }
}

impl<C, W> BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher + BlockEncryptMut,
{
    fn write_buffer(&mut self) -> io::Result<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Buffer already closed"))?;
        let mut blocks_to_encrypt = [std::mem::take(&mut self.buffer)];
        self.cipher.encrypt_blocks_mut(&mut blocks_to_encrypt);
        inner.write_all(&blocks_to_encrypt[0])?;
        Ok(())
    }
}

impl<'a, C, W> BlockCipherWriterExt<'a, W> for BlockCipherWriter<C, W>
where
    W: io::Write + 'a,
    C: BlockCipher + BlockEncryptMut,
{
    fn finish(&mut self) -> io::Result<W> {
        if self.inner.is_some() {
            Pkcs7::pad(&mut self.buffer, self.buf_idx);
            self.write_buffer()?;
            Ok(self.inner.take().unwrap())
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Buffer already closed",
            ))
        }
    }
}

impl<C, W> io::Write for BlockCipherWriter<C, W>
where
    W: io::Write,
    C: BlockCipher + BlockEncryptMut,
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
        if let Some(inner) = self.inner.as_mut() {
            inner.flush()?
        }
        Ok(())
    }
}
