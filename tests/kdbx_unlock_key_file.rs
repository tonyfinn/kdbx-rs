use std::fs;
use std::path::PathBuf;

#[test]
fn kdbx4_argon2d_key_file() -> Result<(), kdbx_rs::Error> {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("test_input");
    file_path.push("kdbx4-argon2d-key-file.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();
    let key_file = Some(b"key-file".to_vec());
    let key = kdbx_rs::CompositeKey::new(Some(String::from("kdbxrs")), key_file);
    Ok(db.unlock(&key).map(|_| ())?)
}
