use kdbx_rs;
use kdbx_rs::types::{Entry, Field, Group, Times};

use chrono::NaiveDate;
use std::fs::read_to_string;
use std::path::PathBuf;
use uuid::Uuid;

fn sample_times() -> Times {
    Times {
        last_access_time: NaiveDate::from_ymd(2020, 05, 01).and_hms(1, 2, 3),
        last_modification_time: NaiveDate::from_ymd(2020, 04, 01).and_hms(1, 2, 3),
        creation_time: NaiveDate::from_ymd(2020, 04, 01).and_hms(1, 1, 3),
        location_changed: NaiveDate::from_ymd(2020, 04, 01).and_hms(1, 1, 3),
        expiry_time: NaiveDate::from_ymd(2020, 04, 01).and_hms(1, 1, 3),
        expires: false,
        usage_count: 1,
    }
}

#[test]
fn generate_xml() -> Result<(), kdbx_rs::Error> {
    let mut expected_path = PathBuf::new();
    expected_path.push(env!("CARGO_MANIFEST_DIR"));
    expected_path.push("res");
    expected_path.push("tests");
    expected_path.push("generate_xml.xml");

    let expected_xml_string = read_to_string(expected_path).unwrap().replace("\r\n", "\n");

    let mut db = kdbx_rs::Database::default();
    db.meta.database_name = "BarName".to_string();
    db.meta.database_description = "BazDesc".to_string();
    let mut group = Group::default();
    group.name = "FooGroup".to_string();
    group.uuid = Uuid::from_u128(0x12345678);
    group.times = sample_times();
    let mut entry = Entry::default();
    entry.add_field(Field::new("Title", "Bar"));
    entry.add_field(Field::new("Password", "kdbxrs"));
    entry.uuid = Uuid::from_u128(0x654321);
    entry.times = sample_times();
    group.entries.push(entry);
    db.groups.push(group);

    let mut output_buffer = Vec::new();
    kdbx_rs::xml::write_xml(&mut output_buffer, &db)?;
    let xml_string = String::from_utf8(output_buffer).unwrap();
    assert_eq!(expected_xml_string, xml_string);
    Ok(())
}
