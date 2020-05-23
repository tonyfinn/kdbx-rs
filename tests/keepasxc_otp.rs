use kdbx_rs;
use std::fs;
use std::path::PathBuf;

#[test]
fn keepassxc_otp_read_secret() -> Result<(), kdbx_rs::Error> {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("test_input");
    file_path.push("keepassxc-otp.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();
    let key = kdbx_rs::CompositeKey::from_password("kdbxrs");
    let db = db.unlock(&key)?;
    let xml = db.database();
    assert_eq!("ABCDEFGHIJKLMNOP", xml.groups[0].entries[0].otp().unwrap().secret().unwrap());

    Ok(())
}