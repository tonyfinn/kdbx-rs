use crate::utils::buffer;
use derive_more::TryInto;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{self, Read};
use thiserror::Error;

const TAG_UINT32: u8 = 0x04;
const TAG_UINT64: u8 = 0x05;
const TAG_BOOLEAN: u8 = 0x08;
const TAG_INT32: u8 = 0x0C;
const TAG_INT64: u8 = 0x0D;
const TAG_STRING: u8 = 0x18;
const TAG_ARRAY: u8 = 0x42;

#[derive(Error, Debug)]
/// Failures to parse a variant dictionary
pub enum VariantParseError {
    /// Failed reading data from source
    #[error("Could not read from file")]
    Io(#[from] std::io::Error),
    /// String field contained invalid UTF-8
    #[error("Could not decode string")]
    DecodeString(#[from] std::string::FromUtf8Error),
    /// Some field was not the expected size for its type
    #[error("Invalid size for type {ty:?}. Expected {expected:X} bytes but was {actual:X} bytes")]
    InvalidSize {
        /// Type id for the field
        ty: u8,
        /// Expected size for this type
        expected: usize,
        /// Actual size of this type
        actual: usize,
    },
    /// Variant field version unsupported by this library, version too high?
    #[error("Variant field version: {0} too high")]
    VariantFieldVersion(u8),
}

#[derive(PartialEq, Eq, Debug, Clone, TryInto)]
/// A value from a kdbx header map with a type known at runtime
pub enum Value {
    /// 32 bit unsigned int
    Uint32(u32),
    /// 64 bit unsigned int
    Uint64(u64),
    /// True/False option
    Boolean(bool),
    /// 32 bit signed int
    Int32(i32),
    /// 64 bit signed int
    Int64(i64),
    /// String data
    String(String),
    /// Binary data
    Array(Vec<u8>),
    /// Unknown field type
    Unknown(u8, Vec<u8>),
}

impl Value {
    pub(crate) fn tag(&self) -> u8 {
        match self {
            Value::Uint32(_) => TAG_UINT32,
            Value::Uint64(_) => TAG_UINT64,
            Value::Boolean(_) => TAG_BOOLEAN,
            Value::Int32(_) => TAG_INT32,
            Value::Int64(_) => TAG_INT64,
            Value::String(_) => TAG_STRING,
            Value::Array(_) => TAG_ARRAY,
            Value::Unknown(tag, _) => *tag,
        }
    }

    pub(crate) fn data(&self) -> Vec<u8> {
        match self {
            Value::Uint32(val) => val.to_le_bytes().iter().cloned().collect(),
            Value::Uint64(val) => val.to_le_bytes().iter().cloned().collect(),
            Value::Boolean(val) => vec![if *val { 1 } else { 0 }],
            Value::Int32(val) => val.to_le_bytes().iter().cloned().collect(),
            Value::Int64(val) => val.to_le_bytes().iter().cloned().collect(),
            Value::String(val) => val.as_bytes().iter().cloned().collect(),
            Value::Array(val) => val.clone(),
            Value::Unknown(_, val) => val.clone(),
        }
    }

    fn from_bytes(ty: u8, buffer: Vec<u8>) -> Result<Value> {
        let bufsize = buffer.len();
        match ty {
            TAG_UINT32 => Ok(Value::Uint32(u32::from_le_bytes(
                (&*buffer)
                    .try_into()
                    .map_err(|_| VariantParseError::InvalidSize {
                        ty,
                        expected: 4,
                        actual: bufsize,
                    })?,
            ))),
            TAG_UINT64 => Ok(Value::Uint64(u64::from_le_bytes(
                (&*buffer)
                    .try_into()
                    .map_err(|_| VariantParseError::InvalidSize {
                        ty,
                        expected: 8,
                        actual: bufsize,
                    })?,
            ))),
            TAG_BOOLEAN => {
                if buffer.len() != 1 {
                    Err(VariantParseError::InvalidSize {
                        ty,
                        expected: 1,
                        actual: bufsize,
                    })
                } else {
                    Ok(Value::Boolean(buffer[0] == 1))
                }
            }
            TAG_INT32 => Ok(Value::Int32(i32::from_le_bytes(
                (&*buffer)
                    .try_into()
                    .map_err(|_| VariantParseError::InvalidSize {
                        ty,
                        expected: 4,
                        actual: bufsize,
                    })?,
            ))),
            TAG_INT64 => Ok(Value::Int64(i64::from_le_bytes(
                (&*buffer)
                    .try_into()
                    .map_err(|_| VariantParseError::InvalidSize {
                        ty,
                        expected: 8,
                        actual: bufsize,
                    })?,
            ))),
            TAG_STRING => Ok(Value::String(String::from_utf8(buffer)?)),
            TAG_ARRAY => Ok(Value::Array(buffer)),
            _ => Ok(Value::Unknown(ty, buffer)),
        }
    }
}

type Result<T> = std::result::Result<T, VariantParseError>;

/// Map of values from KDBX header with differing types
pub type VariantDict = std::collections::HashMap<String, Value>;

fn parse_variant_dict_entry<T: Read>(ty: u8, input: &mut T) -> Result<(String, Value)> {
    let mut length_buffer = [0u8; 4];

    input.read_exact(&mut length_buffer)?;
    let key_length = i32::from_le_bytes(length_buffer.clone());
    let mut key_buffer: Vec<u8> = buffer(key_length as usize);
    input.read_exact(&mut key_buffer)?;
    let key = String::from_utf8(key_buffer)?;

    input.read_exact(&mut length_buffer)?;
    let value_length = i32::from_le_bytes(length_buffer);
    let mut value_buffer: Vec<u8> = buffer(value_length as usize);
    input.read_exact(&mut value_buffer)?;

    let value = Value::from_bytes(ty, value_buffer)?;

    Ok((key, value))
}

pub(crate) fn parse_variant_dict<T: Read>(mut input: T) -> Result<VariantDict> {
    let mut map = HashMap::new();

    let mut version_buffer = [0u8, 0u8];
    input.read_exact(&mut version_buffer)?;
    let major_version = version_buffer[1];
    if major_version > 1 {
        return Err(VariantParseError::VariantFieldVersion(major_version));
    }

    let mut type_buffer = [0u8];
    input.read_exact(&mut type_buffer)?;
    let mut ty = type_buffer[0];
    while ty != 0 {
        match parse_variant_dict_entry(ty, &mut input) {
            Ok((key, value)) => {
                if let Value::Unknown(ty, _) = value {
                    eprintln!("Warning: Unknown field type {:?}", ty)
                }
                map.insert(key, value);
            }
            Err(e) => return Err(e),
        }
        input.read_exact(&mut type_buffer)?;
        ty = type_buffer[0];
    }

    Ok(map)
}

pub(crate) fn write_variant_dict<W: io::Write>(
    mut output: W,
    vdict: &VariantDict,
) -> io::Result<()> {
    output.write_all(&[0u8, 1u8])?;
    for (name, value) in vdict.iter() {
        output.write_all(&[value.tag()])?;
        output.write_all(&(name.len() as i32).to_le_bytes())?;
        output.write_all(name.as_bytes())?;
        let data = value.data();
        output.write_all(&(data.len() as i32).to_le_bytes())?;
        output.write_all(&data)?;
    }
    output.write_all(&[0])?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn numeric_types() -> Result<()> {
        let data: Vec<u8> = Vec::new()
            .iter()
            .chain(&[0x00, 0x01]) // vdict version 1.0
            // i4 = 12345i32
            .chain(&[0x0C])
            .chain(&2i32.to_le_bytes())
            .chain(&[0x69, 0x34])
            .chain(&4i32.to_le_bytes())
            .chain(&12345i32.to_le_bytes())
            // i8 = 123456789
            .chain(&[0x0D])
            .chain(&2i32.to_le_bytes())
            .chain(&[0x69, 0x38])
            .chain(&8i32.to_le_bytes())
            .chain(&1234567890i64.to_le_bytes())
            // u4 = 54321u32
            .chain(&[0x04])
            .chain(&2i32.to_le_bytes())
            .chain(&[0x75, 0x34])
            .chain(&4i32.to_le_bytes())
            .chain(&54321u32.to_le_bytes())
            // u8 = 9876543210u64
            .chain(&[0x05])
            .chain(&2i32.to_le_bytes())
            .chain(&[0x75, 0x38])
            .chain(&8i32.to_le_bytes())
            .chain(&9876543210u64.to_le_bytes())
            .chain(&[0x00])
            .cloned()
            .collect();

        let parsed = parse_variant_dict(&*data)?;

        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed.get("i4"), Some(&Value::Int32(12345)));
        assert_eq!(parsed.get("i8"), Some(&Value::Int64(1234567890)));
        assert_eq!(parsed.get("u4"), Some(&Value::Uint32(54321)));
        assert_eq!(parsed.get("u8"), Some(&Value::Uint64(9876543210)));

        Ok(())
    }
}
