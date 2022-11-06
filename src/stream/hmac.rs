pub const HMAC_WRITE_BLOCK_SIZE: usize = 1024 * 1024;

use crate::crypto::HmacKey;
use std::io::{self, Read, Write};

pub(crate) struct HMacReader<R>
where
    R: Read,
{
    block_idx: u64,
    buf_idx: usize,
    buffer: Vec<u8>,
    inner: R,
    hmac_key: HmacKey,
}

impl<R: io::Read> HMacReader<R> {
    pub(crate) fn new(inner: R, hmac_key: HmacKey) -> HMacReader<R> {
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

impl<R: Read> Read for HMacReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut remaining_in_buffer = self.buffer.len() - self.buf_idx;

        if remaining_in_buffer == 0 {
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

pub(crate) struct HmacWriter<'a, W>
where
    W: 'a + io::Write,
{
    block_idx: u64,
    buffer: Vec<u8>,
    inner: W,
    hmac_key: HmacKey,
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a, W> HmacWriter<'a, W>
where
    W: 'a + io::Write,
{
    pub(crate) fn new(inner: W, hmac_key: HmacKey) -> HmacWriter<'a, W> {
        HmacWriter {
            block_idx: 0,
            buffer: Vec::with_capacity(HMAC_WRITE_BLOCK_SIZE),
            inner,
            hmac_key,
            _lifetime: std::marker::PhantomData,
        }
    }

    fn write_block(&mut self) -> io::Result<()> {
        let hmac = self
            .hmac_key
            .block_key(self.block_idx)
            .calculate_data_hmac(&self.buffer)
            .unwrap();
        self.inner.write_all(&hmac.into_bytes())?;
        self.inner
            .write_all(&(self.buffer.len() as u32).to_le_bytes())?;
        self.inner.write_all(&self.buffer)?;
        self.buffer.clear();
        self.block_idx += 1;
        Ok(())
    }
}

impl<'a, W: Write> HmacWriter<'a, W>
where
    W: Write,
{
    pub(crate) fn finish(mut self) -> io::Result<W> {
        if !self.buffer.is_empty() {
            self.write_block()?;
        }
        self.write_block()?;
        Ok(self.inner)
    }
}

impl<'a, W: 'a + io::Write> io::Write for HmacWriter<'a, W> {
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
        Ok(())
    }
}
