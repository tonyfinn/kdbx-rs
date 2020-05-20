use super::decoders::{encode_datetime, encode_uuid};
use crate::types::{Database, Entry, Field, Group, MemoryProtection, Meta, Times, Value};
use std::io::Write;
use thiserror::Error;
use xml::writer::events::XmlEvent;
use xml::writer::EventWriter as XmlWriter;

#[derive(Debug, Error)]
/// Failures to write an XML file
pub enum Error {
    /// Underlying XML writer had an error
    #[error("Could not write XML: {0}")]
    Xml(#[from] xml::writer::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn write_bool_tag<W: Write>(writer: &mut XmlWriter<W>, name: &str, value: bool) -> Result<()> {
    writer.write(XmlEvent::start_element(name))?;
    writer.write(XmlEvent::characters(match value {
        true => "True",
        false => "False",
    }))?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_string_tag<W: Write, S: AsRef<str>>(
    writer: &mut XmlWriter<W>,
    name: &str,
    value: S,
) -> Result<()> {
    writer.write(XmlEvent::start_element(name))?;
    writer.write(XmlEvent::characters(value.as_ref()))?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_field<W: Write>(writer: &mut XmlWriter<W>, wrapper: &str, field: &Field) -> Result<()> {
    writer.write(XmlEvent::start_element(wrapper))?;
    write_string_tag(writer, "Key", &field.key)?;
    match &field.value {
        Value::Protected(v) => {
            writer.write(XmlEvent::start_element("Value").attr("Protected", "True"))?;
            writer.write(XmlEvent::characters(&v))?;
            writer.write(XmlEvent::end_element())?;
        }
        Value::Standard(v) => write_string_tag(writer, "Value", &v)?,
        Value::Empty => {
            writer.write(XmlEvent::start_element("Value"))?;
            writer.write(XmlEvent::end_element())?;
        }
    }
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_memory_protection<W: Write>(
    writer: &mut XmlWriter<W>,
    protection: &MemoryProtection,
) -> Result<()> {
    writer.write(XmlEvent::start_element("MemoryProtection"))?;
    write_bool_tag(writer, "ProtectUserName", protection.protect_user_name)?;
    write_bool_tag(writer, "ProtectPassword", protection.protect_password)?;
    write_bool_tag(writer, "ProtectTitle", protection.protect_title)?;
    write_bool_tag(writer, "ProtectNotes", protection.protect_notes)?;
    write_bool_tag(writer, "ProtectURL", protection.protect_url)?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_meta<W: Write>(writer: &mut XmlWriter<W>, meta: &Meta) -> Result<()> {
    writer.write(XmlEvent::start_element("Meta"))?;
    write_string_tag(writer, "Generator", "kdbx-rs")?;
    write_string_tag(writer, "DatabaseName", &meta.database_name)?;
    write_string_tag(writer, "DatabaseDescription", &meta.database_description)?;
    writer.write(XmlEvent::start_element("CustomData"))?;
    for field in &meta.custom_data {
        write_field(writer, "Item", field)?;
    }
    writer.write(XmlEvent::end_element())?;
    write_memory_protection(writer, &meta.memory_protection)?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_times<W: Write>(writer: &mut XmlWriter<W>, times: &Times) -> Result<()> {
    writer.write(XmlEvent::start_element("Times"))?;
    write_string_tag(
        writer,
        "LastModificationTime",
        encode_datetime(times.last_modification_time),
    )?;
    write_string_tag(writer, "CreationTime", encode_datetime(times.creation_time))?;
    write_string_tag(
        writer,
        "LastAccessTime",
        encode_datetime(times.last_access_time),
    )?;
    write_string_tag(
        writer,
        "LocationChanged",
        encode_datetime(times.location_changed),
    )?;
    write_string_tag(writer, "ExpiryTime", encode_datetime(times.expiry_time))?;
    write_string_tag(writer, "UsageCount", times.usage_count.to_string())?;
    write_bool_tag(writer, "Expires", times.expires)?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_entry<W: Write>(writer: &mut XmlWriter<W>, entry: &Entry) -> Result<()> {
    writer.write(XmlEvent::start_element("Entry"))?;
    write_string_tag(writer, "UUID", &encode_uuid(&entry.uuid))?;
    write_times(writer, &entry.times)?;
    for field in &entry.fields {
        write_field(writer, "String", field)?;
    }
    if entry.history.len() > 0 {
        writer.write(XmlEvent::start_element("History"))?;
        for old_entry in &entry.history {
            write_entry(writer, old_entry)?;
        }
        writer.write(XmlEvent::end_element())?;
    }
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_group<W: Write>(writer: &mut XmlWriter<W>, group: &Group) -> Result<()> {
    writer.write(XmlEvent::start_element("Group"))?;
    write_string_tag(writer, "UUID", encode_uuid(&group.uuid))?;
    write_string_tag(writer, "Name", &group.name)?;
    write_times(writer, &group.times)?;
    for entry in &group.entries {
        write_entry(writer, &entry)?;
    }
    for group in &group.children {
        write_group(writer, &group)?;
    }
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

/// Write the decrypted XML for a database to a file
pub fn write_xml<W: Write>(output: W, database: &Database) -> Result<()> {
    let config = xml::EmitterConfig::default()
        .perform_indent(true)
        .indent_string("\t");
    let mut writer = xml::EventWriter::new_with_config(output, config);
    writer.write(XmlEvent::start_element("KeePassFile"))?;
    write_meta(&mut writer, &database.meta)?;
    writer.write(XmlEvent::start_element("Root"))?;
    for group in &database.groups {
        write_group(&mut writer, group)?;
    }
    writer.write(XmlEvent::end_element())?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}
