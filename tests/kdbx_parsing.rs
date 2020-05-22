use kdbx_rs;
use std::fs;
use std::path::PathBuf;

#[test]
fn kdbx4_parsing() -> Result<(), kdbx_rs::Error> {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("kdbx4-argon2.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();
    let key = kdbx_rs::CompositeKey::from_password("kdbxrs");
    let db = db.unlock(&key)?;
    let xml = kdbx_rs::xml::parse_xml(db.raw_xml().unwrap())?;

    assert_eq!(1, xml.groups.len());
    assert_eq!("Root", xml.groups[0].name);
    assert_eq!(
        "cd4233f1-fac2-4272-b309-3c5e7df90097",
        xml.groups[0].uuid.to_string()
    );
    assert_eq!(1, xml.groups[0].entries.len());
    assert_eq!(
        "d5870a13-f968-41c5-a233-69b7bc86a628",
        xml.groups[0].entries[0].uuid.to_string()
    );
    assert_eq!(1, xml.groups[0].entries[0].history.len());
    assert_eq!(
        "d5870a13-f968-41c5-a233-69b7bc86a628",
        xml.groups[0].entries[0].history[0].uuid.to_string()
    );

    Ok(())
}

#[test]
fn kdbx4_parsing_twofish() -> Result<(), kdbx_rs::Error> {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("kdbx4-argon2-twofish.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();
    let key = kdbx_rs::CompositeKey::from_password("kdbxrs");
    let db = db.unlock(&key)?;
    let xml = kdbx_rs::xml::parse_xml(db.raw_xml().unwrap())?;

    assert_eq!(1, xml.groups.len());
    assert_eq!("Root", xml.groups[0].name);
    assert_eq!(
        "cd4233f1-fac2-4272-b309-3c5e7df90097",
        xml.groups[0].uuid.to_string()
    );
    assert_eq!(1, xml.groups[0].entries.len());
    assert_eq!(
        "d5870a13-f968-41c5-a233-69b7bc86a628",
        xml.groups[0].entries[0].uuid.to_string()
    );
    assert_eq!(1, xml.groups[0].entries[0].history.len());
    assert_eq!(
        "d5870a13-f968-41c5-a233-69b7bc86a628",
        xml.groups[0].entries[0].history[0].uuid.to_string()
    );

    Ok(())
}

