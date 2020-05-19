use kdbx_rs::crypto;
use kdbx_rs::database;
use kdbx_rs::header;
use std::fs;
use std::path::PathBuf;

#[test]
fn load_kdbx4_argon2() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("kdbx4-argon2.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = database::read(file).unwrap();

    assert_eq!(db.header().cipher, crypto::Cipher::Aes256);
    assert_eq!(db.header().compression_type, header::CompressionType::Gzip);
    assert_eq!(db.header().other_headers, Vec::new());
    assert_eq!(
        db.header().master_seed,
        vec![
            187, 130, 104, 230, 238, 100, 150, 159, 210, 24, 51, 168, 41, 44, 189, 207, 141, 49,
            95, 3, 244, 128, 203, 234, 155, 199, 90, 222, 128, 131, 215, 51
        ],
    );
    assert_eq!(
        db.header().encryption_iv,
        vec![86, 5, 40, 43, 154, 66, 96, 183, 24, 238, 46, 80, 150, 58, 144, 40],
    );
    assert_eq!(
        db.header().kdf_params,
        crypto::KdfOptions::Argon2 {
            iterations: 26,
            lanes: 2,
            memory_bytes: 65536 * 1024,
            version: 0x13,
            salt: vec![
                49, 180, 104, 138, 38, 29, 245, 88, 126, 134, 89, 85, 108, 223, 206, 86, 38, 174,
                13, 55, 195, 100, 215, 51, 30, 44, 254, 164, 107, 10, 189, 218
            ],
        }
    );
}

#[test]
fn load_kdbx4_aes256() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("kdbx4-aes256.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = database::read(file).unwrap();
    assert_eq!(
        db.header().kdf_params,
        crypto::KdfOptions::Aes {
            rounds: 33908044,
            salt: vec![
                248, 143, 74, 209, 60, 251, 247, 195, 28, 176, 139, 132, 158, 203, 40, 14, 146, 7,
                250, 201, 104, 43, 51, 248, 107, 115, 120, 186, 178, 164, 10, 3
            ]
        }
    );
}

#[test]
fn load_kdbx4_aes256_legacy() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("kdbx4-aes256-legacy.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = database::read(file).unwrap();
    assert_eq!(
        db.header().kdf_params,
        crypto::KdfOptions::Aes {
            rounds: 31130267,
            salt: vec![
                180, 76, 210, 106, 16, 174, 0, 214, 176, 158, 130, 118, 83, 207, 237, 52, 172, 84,
                127, 37, 150, 154, 40, 152, 167, 205, 218, 233, 142, 149, 155, 224
            ]
        }
    );
}
