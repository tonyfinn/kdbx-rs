use kdbx_rs::crypto;
use kdbx_rs::database;

use std::fs;
use std::path::PathBuf;

#[test]
fn kdbx4_argon2() -> Result<(), database::UnlockError> {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("kdbx4-argon2-uncompressed.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = database::read(file).unwrap();
    let key = crypto::CompositeKey::pwonly("kdbxrs");
    db.unlock(key)
        .map(|_| ())
        .map_err(|e| e.0)
}
