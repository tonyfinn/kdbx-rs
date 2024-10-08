//! Generates a sample database using kdbxrs
//!
//! Primarily for verifying kdbx-rs changes

use kdbx_rs::database::{Entry, Times};
use kdbx_rs::{CompositeKey, Database, Error, Kdbx};

use chrono::NaiveDate;
use std::fs::File;
use std::path::PathBuf;
use uuid::Uuid;

fn set_sample_times(times: &mut Times) {
    times.last_access_time = NaiveDate::from_ymd_opt(2020, 5, 1)
        .unwrap()
        .and_hms_opt(1, 2, 3)
        .unwrap();
    times.last_modification_time = NaiveDate::from_ymd_opt(2020, 4, 1)
        .unwrap()
        .and_hms_opt(1, 2, 3)
        .unwrap();
    times.creation_time = NaiveDate::from_ymd_opt(2020, 4, 1)
        .unwrap()
        .and_hms_opt(1, 1, 3)
        .unwrap();
    times.location_changed = NaiveDate::from_ymd_opt(2020, 4, 1)
        .unwrap()
        .and_hms_opt(1, 1, 3)
        .unwrap();
    times.expiry_time = NaiveDate::from_ymd_opt(2020, 4, 1)
        .unwrap()
        .and_hms_opt(1, 1, 3)
        .unwrap();
    times.expires = false;
    times.usage_count = 1;
}

fn main() -> Result<(), Error> {
    let mut expected_path = PathBuf::new();
    expected_path.push(env!("CARGO_MANIFEST_DIR"));
    expected_path.push("res");
    expected_path.push("tests");
    expected_path.push("generate_xml.xml");

    let mut db = Database::default();
    db.set_name("BarName");
    db.set_description("BazDesc".to_string());
    let root = db.root_mut();
    root.set_name("Root");
    root.set_uuid(Uuid::from_u128(0x1234_5678));
    set_sample_times(root.times_mut());
    let mut entry = Entry::default();
    entry.set_title("Bar");
    entry.set_password("kdbxrs");
    entry.set_uuid(Uuid::from_u128(0x0065_4321));
    set_sample_times(entry.times_mut());
    root.add_entry(entry);

    let output_path = PathBuf::from("kdbx_rs.kdbx");
    let mut file = File::create(output_path).expect("Could not open output file");

    let mut kdbx = Kdbx::from_database(db);
    kdbx.set_key(CompositeKey::from_password("kdbxrs"))?;
    kdbx.write(&mut file).expect("Could not write to file");
    Ok(())
}
