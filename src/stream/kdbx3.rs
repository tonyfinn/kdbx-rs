use crate::crypto;
use std::io::{self, Read};

pub struct HashedBlockReader<R>
where
    R: Read,
{
    inner: R,
    buffer: Vec<u8>,
    buf_idx: usize,
}

impl<R> HashedBlockReader<R>
where
    R: Read,
{
    pub(crate) fn new(inner: R) -> HashedBlockReader<R> {
        HashedBlockReader {
            inner,
            buffer: Vec::new(),
            buf_idx: 0,
        }
    }

    fn buffer_next_block(&mut self) -> io::Result<usize> {
        let mut id_buf = [0u8; 4];
        self.inner.read_exact(&mut id_buf)?;
        let mut hash_buf = [0u8; 32];
        self.inner.read_exact(&mut hash_buf)?;
        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        self.buffer.resize_with(len, Default::default);
        self.inner.read_exact(&mut self.buffer)?;
        self.buf_idx = 0;
        if crypto::verify_sha256(&self.buffer, &hash_buf) {
            Ok(len)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Block failed hash verification",
            ))
        }
    }
}

impl<R> Read for HashedBlockReader<R>
where
    R: Read,
{
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
