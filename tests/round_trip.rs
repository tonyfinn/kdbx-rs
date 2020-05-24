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
fn round_trip() -> Result<(), kdbx_rs::Error> {
    let mut db = kdbx_rs::Database::default();
    db.meta.database_name = DATABASE_NAME.to_string();
    db.meta.database_description = DATABASE_DESC.to_string();
    let mut group = Group::default();
    group.set_name(GROUP_NAME);
    let group_times = group.times.clone();
    let mut entry = Entry::default();
    entry.add_field(Field::new("Title", ENTRY_NAME));
    entry.set_password(ENTRY_PASSWORD);
    entry.add_field(Field::new("Password", ENTRY_PASSWORD));
    let entry_times = entry.times.clone();
    group.entries.push(entry);
    db.groups.push(group);
    let mut kdbx = Kdbx::from_database(db);

    let mut output_buf = Vec::new();
    kdbx.set_key(key())?;
    kdbx.write(&mut output_buf)?;

    let reparsed = kdbx_rs::from_reader(&*output_buf)?;
    let unlocked = reparsed.unlock(&key())?;
    assert_eq!(unlocked.meta().database_name, DATABASE_NAME);
    assert_eq!(unlocked.meta().database_description, DATABASE_DESC);
    let root = unlocked.root().unwrap();
    assert_eq!(root.name(), GROUP_NAME);
    assert_eq!(root.entries[0].title().unwrap(), ENTRY_NAME);
    assert_eq!(root.entries[0].password().unwrap(), ENTRY_PASSWORD);
    assert_eq!(root.times, group_times);
    assert_eq!(root.entries[0].times, entry_times);

    Ok(())
}
