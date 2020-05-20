use super::decoders::{decode_datetime, decode_uuid};
use crate::types::{Database, Entry, Field, Group, MemoryProtection, Meta, Times, Value};
use chrono::NaiveDateTime;
use std::io::Read;
use thiserror::Error;
use uuid::Uuid;
use xml::reader::{EventReader, XmlEvent};

#[derive(Debug, Error)]
/// Error encountered parsing XML
pub enum Error {
    /// Error from the underlying XML parser
    #[error("Error parsing database XML: {0}")]
    Xml(String),
    /// A field has an empty name
    #[error("A field has an empty name")]
    KeyEmptyName,
    /// A UUID field is not valid
    #[error("UUID is not valid")]
    InvalidUuid,
    /// A UUID field is not valid
    #[error("Datetime is not valid")]
    InvalidDatetime,
    /// A numeric field is not valid
    #[error("Invalid numeric value")]
    InvalidNumber,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<xml::reader::Error> for Error {
    fn from(e: xml::reader::Error) -> Error {
        Error::Xml(e.msg().to_string())
    }
}

fn parse_string<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Option<String>> {
    let mut content = None;
    loop {
        match xml_event_reader.next()? {
            XmlEvent::Characters(chardata) => {
                content = content.map_or_else(
                    || Some(chardata.clone()),
                    |mut existing: String| {
                        existing.push_str(&chardata);
                        Some(existing)
                    },
                )
            }
            XmlEvent::EndElement { .. } => break,
            _ => {}
        }
    }
    Ok(content)
}

macro_rules! parse_numeric_type {
    ($name:ident, $ty:ty) => {
        fn $name<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Option<$ty>> {
            parse_string(xml_event_reader)?
                .map(|num| num.parse())
                .transpose()
                .map_err(|_| Error::InvalidNumber)
        }
    };
}

parse_numeric_type!(parse_u32, u32);

fn parse_uuid<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Uuid> {
    parse_string(xml_event_reader)?
        .and_then(|uuid| decode_uuid(&uuid))
        .ok_or(Error::InvalidUuid)
}

fn parse_datetime<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<NaiveDateTime> {
    parse_string(xml_event_reader)?
        .and_then(|dt| decode_datetime(&dt))
        .ok_or(Error::InvalidUuid)
}

fn parse_bool<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<bool> {
    Ok(parse_string(xml_event_reader)?
        .map(|b| b.to_lowercase() == "true")
        .unwrap_or_default())
}

fn parse_field<R: Read>(xml_event_reader: &mut EventReader<R>, tag_name: &str) -> Result<Field> {
    let mut field = Field::default();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } if &name.local_name == "Key" => {
                field.key = parse_string(xml_event_reader)
                    .and_then(|val| val.ok_or(Error::KeyEmptyName))?;
            }
            XmlEvent::StartElement {
                name, attributes, ..
            } if &name.local_name == "Value" => {
                let protected = attributes.iter().any(|attr| {
                    attr.name.local_name == "Protected" && attr.value.to_lowercase() == "true"
                });
                field.value = if let Some(contents) = parse_string(xml_event_reader)? {
                    if protected {
                        Value::Protected(contents)
                    } else {
                        Value::Standard(contents)
                    }
                } else {
                    Value::Empty
                }
            }
            XmlEvent::EndElement { name, .. } if &name.local_name == tag_name => break,
            _ => {}
        }
    }
    Ok(field)
}

fn parse_history<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Vec<Entry>> {
    let mut history = Vec::new();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } if &name.local_name == "Entry" => {
                history.push(parse_entry(xml_event_reader)?);
            }
            XmlEvent::EndElement { name, .. } if &name.local_name == "History" => break,
            _ => {}
        }
    }
    Ok(history)
}

fn parse_times<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Times> {
    let mut times = Times::default();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if &name.local_name == "LastModificationTime" {
                    times.last_modification_time = parse_datetime(xml_event_reader)?;
                } else if &name.local_name == "LastAccessTime" {
                    times.last_access_time = parse_datetime(xml_event_reader)?;
                } else if &name.local_name == "CreationTime" {
                    times.creation_time = parse_datetime(xml_event_reader)?;
                } else if &name.local_name == "ExpiryTime" {
                    times.expiry_time = parse_datetime(xml_event_reader)?;
                } else if &name.local_name == "LocationChanged" {
                    times.location_changed = parse_datetime(xml_event_reader)?;
                } else if &name.local_name == "Expires" {
                    times.expires = parse_bool(xml_event_reader)?;
                } else if &name.local_name == "UsageCount" {
                    times.usage_count = parse_u32(xml_event_reader)?.unwrap_or_default();
                }
            }
            XmlEvent::EndElement { name, .. } if &name.local_name == "Times" => break,
            _ => {}
        }
    }
    Ok(times)
}

fn parse_entry<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Entry> {
    let mut entry = Entry::default();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if &name.local_name == "History" {
                    entry.history = parse_history(xml_event_reader)?;
                } else if &name.local_name == "String" {
                    entry.fields.push(parse_field(xml_event_reader, "String")?);
                } else if &name.local_name == "UUID" {
                    entry.uuid = parse_uuid(xml_event_reader)?;
                } else if &name.local_name == "Times" {
                    entry.times = parse_times(xml_event_reader)?;
                }
            }
            XmlEvent::EndElement { name, .. } if &name.local_name == "Entry" => break,
            _ => {}
        }
    }
    Ok(entry)
}

fn parse_group<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Group> {
    let mut group = Group::default();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if &name.local_name == "Group" {
                    group.children.push(parse_group(xml_event_reader)?);
                } else if &name.local_name == "Entry" {
                    group.entries.push(parse_entry(xml_event_reader)?);
                } else if &name.local_name == "UUID" {
                    group.uuid = parse_uuid(xml_event_reader)?;
                } else if &name.local_name == "Name" {
                    group.name = parse_string(xml_event_reader)?.unwrap_or("".to_string());
                } else if &name.local_name == "Times" {
                    group.times = parse_times(xml_event_reader)?;
                }
            }
            XmlEvent::EndElement { name, .. } if &name.local_name == "Group" => break,
            _ => {}
        }
    }
    Ok(group)
}

fn parse_root<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Vec<Group>> {
    let mut groups = Vec::new();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } if &name.local_name == "Group" => {
                groups.push(parse_group(xml_event_reader)?);
            }
            XmlEvent::EndElement { name, .. } if &name.local_name == "Root" => break,
            _ => {}
        }
    }
    Ok(groups)
}

fn parse_custom_data<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Vec<Field>> {
    let mut fields = Vec::new();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } => match name.local_name.as_ref() {
                "Item" => {
                    fields.push(parse_field(xml_event_reader, "Item")?);
                }
                _ => {}
            },
            XmlEvent::EndElement { name, .. } if &name.local_name == "CustomData" => break,
            _ => {}
        }
    }
    Ok(fields)
}

fn parse_memory_protection<R: Read>(
    xml_event_reader: &mut EventReader<R>,
) -> Result<MemoryProtection> {
    let mut protection = MemoryProtection::default();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } => match name.local_name.as_ref() {
                "ProtectTitle" => {
                    protection.protect_title = parse_bool(xml_event_reader)?;
                }
                "ProtectUserName" => {
                    protection.protect_user_name = parse_bool(xml_event_reader)?;
                }
                "ProtectPassword" => {
                    protection.protect_password = parse_bool(xml_event_reader)?;
                }
                "ProtectURL" => {
                    protection.protect_url = parse_bool(xml_event_reader)?;
                }
                "ProtectNotes" => {
                    protection.protect_notes = parse_bool(xml_event_reader)?;
                }
                _ => {}
            },
            XmlEvent::EndElement { name, .. } if &name.local_name == "MemoryProtection" => break,
            _ => {}
        }
    }
    Ok(protection)
}

fn parse_meta<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Meta> {
    let mut meta = Meta::default();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } => match name.local_name.as_ref() {
                "Generator" => {
                    meta.generator = parse_string(xml_event_reader)?.unwrap_or_default();
                }
                "DatabaseName" => {
                    meta.database_name = parse_string(xml_event_reader)?.unwrap_or_default();
                }
                "DatabaseDescription" => {
                    meta.database_description = parse_string(xml_event_reader)?.unwrap_or_default();
                }
                "CustomData" => {
                    meta.custom_data = parse_custom_data(xml_event_reader)?;
                }
                "MemoryProtection" => {
                    meta.memory_protection = parse_memory_protection(xml_event_reader)?;
                }
                _ => {}
            },
            XmlEvent::EndElement { name, .. } if &name.local_name == "Meta" => break,
            _ => {}
        }
    }
    Ok(meta)
}

fn parse_file<R: Read>(xml_event_reader: &mut EventReader<R>) -> Result<Database> {
    let mut db = Database::default();
    loop {
        match xml_event_reader.next()? {
            XmlEvent::StartElement { name, .. } if &name.local_name == "Root" => {
                db.groups = parse_root(xml_event_reader)?;
            }
            XmlEvent::StartElement { name, .. } if &name.local_name == "Meta" => {
                db.meta = parse_meta(xml_event_reader)?;
            }
            XmlEvent::EndElement { name, .. } if &name.local_name == "KeePassFile" => break,
            _ => {}
        }
    }
    Ok(db)
}

/// Parse decrypted XML into a database
pub fn parse_xml<R: Read>(xml_data: R) -> Result<Database> {
    let xml_config = xml::ParserConfig::new()
        .trim_whitespace(true)
        .cdata_to_characters(true);
    let mut xml_event_reader = EventReader::new_with_config(xml_data, xml_config);
    parse_file(&mut xml_event_reader)
}
