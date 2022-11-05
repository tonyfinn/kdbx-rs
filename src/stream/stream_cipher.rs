use cipher::StreamCipher;
use std::io::{self, Read, Write};

pub(crate) struct StreamCipherReader<C, R>
where
    C: StreamCipher,
    R: Read,
{
    inner: R,
    cipher: C,
}

impl<C, R> StreamCipherReader<C, R>
where
    C: StreamCipher,
    R: Read,
{
    pub(crate) fn new(inner: R, cipher: C) -> StreamCipherReader<C, R> {
        StreamCipherReader { inner, cipher }
    }
}

impl<C, R> Read for StreamCipherReader<C, R>
where
    C: StreamCipher,
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.cipher.apply_keystream(&mut buf[0..read]);
        Ok(read)
    }
}

pub(crate) struct StreamCipherWriter<C, W>
where
    C: StreamCipher,
    W: Write,
{
    inner: Option<W>,
    cipher: C,
}

impl<C, W> StreamCipherWriter<C, W>
where
    C: StreamCipher,
    W: Write,
{
    pub(crate) fn new(inner: W, cipher: C) -> StreamCipherWriter<C, W> {
        StreamCipherWriter {
            inner: Some(inner),
            cipher,
        }
    }
}

impl<C, W> Write for StreamCipherWriter<C, W>
where
    C: StreamCipher,
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(ref mut inner) = self.inner {
            let mut vec = buf.to_vec();
            self.cipher.apply_keystream(&mut vec);
            inner.write_all(&vec)?;
            Ok(vec.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream already closed",
            ))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(ref mut inner) = self.inner {
            inner.flush()
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream already closed",
            ))
        }
    }
}

pub(crate) trait StreamCipherWriterExt<W>: Write
where
    W: Write,
{
    fn into_inner(&mut self) -> W;
}

impl<C, W> StreamCipherWriterExt<W> for StreamCipherWriter<C, W>
where
    C: StreamCipher,
    W: Write,
{
    fn into_inner(&mut self) -> W {
        self.inner.take().unwrap()
    }
}
