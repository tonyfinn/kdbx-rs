use kdbx_rs::kdb;
use std::fs;
use std::path::PathBuf;


#[test]
fn load_kdb_aes128() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("test_input");
    file_path.push("kdb-aes128.kdb");

    let file = fs::File::open(file_path).unwrap();

    let db = kdb::from_reader(file).unwrap();
    println!("{:?}", db);
    assert_eq!(
        db.header().cipher,
        kdbx_rs::binary::Cipher::Aes128
    );
    assert_eq!(
        db.header().key_rounds,
        1000
    );
}

#[test]
fn load_kdb_twofish() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("test_input");
    file_path.push("kdb-twofish.kdb");

    let file = fs::File::open(file_path).unwrap();

    let db = kdb::from_reader(file).unwrap();
    println!("{:?}", db);
    assert_eq!(
        db.header().cipher,
        kdbx_rs::binary::Cipher::TwoFish
    );
    assert_eq!(
        db.header().key_rounds,
        10000
    );
}
