use std::io;
use uuid::Uuid;

pub(crate) fn value_from_uuid_table<T: Clone>(
    table: &[(&str, T)],
    lookup: uuid::Uuid,
) -> Option<T> {
    for (uuid_str, ref value) in table.iter() {
        let item_uuid = Uuid::parse_str(uuid_str).ok()?;
        if item_uuid == lookup {
            return Some(value.clone());
        }
    }
    None
}

pub(crate) fn uuid_from_uuid_table<T: Clone + PartialEq>(
    table: &[(&str, T)],
    lookup: T,
) -> Option<uuid::Uuid> {
    for (uuid_str, ref value) in table.iter() {
        let item_uuid = Uuid::parse_str(uuid_str).ok()?;
        if value.clone() == lookup {
            return Some(item_uuid);
        }
    }
    None
}

pub(crate) fn buffer(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    v.resize_with(len, Default::default);
    v
}

pub(crate) struct CachingReader<'a, I>
where
    I: io::Read,
{
    data: Vec<u8>,
    inner: &'a mut I,
}

impl<'a, I: io::Read> io::Read for CachingReader<'a, I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.read(buf)?;
        self.data.extend(buf.iter().cloned());
        Ok(size)
    }
}

impl<'a, I: io::Read> CachingReader<'a, I> {
    pub(crate) fn new(inner: &'a mut I) -> CachingReader<'a, I> {
        CachingReader {
            data: Vec::new(),
            inner,
        }
    }

    pub(crate) fn into_inner(self) -> (Vec<u8>, &'a mut I) {
        (self.data, self.inner)
    }
}

pub fn to_hex_string(data: &[u8]) -> String {
    let mut output = String::new();

    for byte in data {
        output.push_str(&format!("{:x}", byte))
    }

    output
}
