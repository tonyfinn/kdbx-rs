use kdbx_rs::binary::KdfParams;
use kdbx_rs::database::{Entry, Field, Group};
use kdbx_rs::{self, CompositeKey, Kdbx};

const DATABASE_NAME: &str = "BarName";
const DATABASE_DESC: &str = "BazDesc";
const GROUP_NAME: &str = "FooGroup";
const ENTRY_NAME: &str = "Bar";
const ENTRY_PASSWORD: &str = "kdbxrs";
const DATABASE_PASSWORD: &str = "blahblahblah";
const DATABASE_KEY_FILE: [u8; 3] = [0x20, 0x40, 0x60];

fn key() -> CompositeKey {
    CompositeKey::new(
        Some(DATABASE_PASSWORD.into()),
        Some(DATABASE_KEY_FILE.as_ref().to_vec()),
    )
}

#[test]
fn round_trip_default() -> Result<(), kdbx_rs::Error> {
    let mut db = kdbx_rs::Database::default();
    db.set_name(DATABASE_NAME.to_string());
    db.set_description(DATABASE_DESC.to_string());
    let mut group = Group::default();
    group.set_name(GROUP_NAME);
    let group_times = group.times().clone();
    let mut entry = Entry::default();
    entry.add_field(Field::new("Title", ENTRY_NAME));
    entry.set_password(ENTRY_PASSWORD);
    entry.add_field(Field::new("Password", ENTRY_PASSWORD));
    let entry_times = entry.times().clone();
    group.add_entry(entry);
    db.replace_root(group);
    let mut kdbx = Kdbx::from_database(db);

    let mut output_buf = Vec::new();
    kdbx.set_key(key())?;
    kdbx.write(&mut output_buf)?;

    let reparsed = kdbx_rs::from_reader(&*output_buf)?;
    let unlocked = reparsed.unlock(&key())?;
    assert_eq!(unlocked.meta().database_name, DATABASE_NAME);
    assert_eq!(unlocked.meta().database_description, DATABASE_DESC);
    let root = unlocked.root();
    assert_eq!(root.name(), GROUP_NAME);
    let first_entry: &Entry = root.entries().collect::<Vec<_>>()[0];
    assert_eq!(first_entry.title().unwrap(), ENTRY_NAME);
    assert_eq!(first_entry.password().unwrap(), ENTRY_PASSWORD);
    assert_eq!(root.times(), &group_times);
    assert_eq!(first_entry.times(), &entry_times);

    Ok(())
}

#[test]
fn round_trip_argon2id() -> Result<(), kdbx_rs::Error> {
    let mut db = kdbx_rs::Database::default();
    db.set_name(DATABASE_NAME.to_string());
    db.set_description(DATABASE_DESC.to_string());
    let mut group = Group::default();
    group.set_name(GROUP_NAME);
    let group_times = group.times().clone();
    let mut entry = Entry::default();
    entry.add_field(Field::new("Title", ENTRY_NAME));
    entry.set_password(ENTRY_PASSWORD);
    entry.add_field(Field::new("Password", ENTRY_PASSWORD));
    let entry_times = entry.times().clone();
    group.add_entry(entry);
    db.replace_root(group);
    let mut kdbx = Kdbx::from_database(db);
    if let KdfParams::Argon2 { variant, .. } = &mut kdbx.header_mut().kdf_params {
        *variant = argon2::Variant::Argon2id;
    }

    let mut output_buf = Vec::new();
    kdbx.set_key(key())?;
    kdbx.write(&mut output_buf)?;

    let reparsed = kdbx_rs::from_reader(&*output_buf)?;
    let unlocked = reparsed.unlock(&key())?;
    assert_eq!(unlocked.meta().database_name, DATABASE_NAME);
    assert_eq!(unlocked.meta().database_description, DATABASE_DESC);
    let root = unlocked.root();
    assert_eq!(root.name(), GROUP_NAME);
    let first_entry: &Entry = root.entries().collect::<Vec<_>>()[0];
    assert_eq!(first_entry.title().unwrap(), ENTRY_NAME);
    assert_eq!(first_entry.password().unwrap(), ENTRY_PASSWORD);
    assert_eq!(root.times(), &group_times);
    assert_eq!(first_entry.times(), &entry_times);

    Ok(())
}
