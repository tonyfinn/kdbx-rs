
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
    let db = db.unlock(&key).map_err(|e| e.0)?;
    let xml = kdbx_rs::parse_xml(db.xml_data())?;

    assert_eq!(1, xml.groups.len());
    assert_eq!(1, xml.groups[0].entries.len());
    assert_eq!(1, xml.groups[0].entries[0].history.len());

    Ok(())
}
