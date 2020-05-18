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
    assert_eq!(db.header().compression_type, header::CompressionType::None);
    assert_eq!(db.header().other_headers, Vec::new());
    assert_eq!(
        db.header().master_seed,
        vec![
            178, 96, 53, 92, 11, 123, 129, 106, 162, 5, 167, 71, 204, 76, 187, 247, 58, 243, 196,
            145, 95, 83, 172, 11, 163, 211, 17, 111, 128, 35, 1, 203
        ]
    );
    assert_eq!(
        db.header().encryption_iv,
        vec![153, 129, 101, 36, 161, 230, 64, 41, 228, 230, 7, 235, 197, 40, 230, 5]
    );
    assert_eq!(
        db.header().kdf_params,
        crypto::KdfOptions::Argon2 {
            iterations: 26,
            lanes: 2,
            memory_bytes: 65536 * 1024,
            version: 0x13,
            salt: vec![
                218, 60, 221, 254, 167, 184, 253, 73, 185, 140, 245, 215, 114, 183, 61, 196, 79,
                39, 103, 115, 53, 157, 238, 99, 63, 88, 99, 83, 60, 134, 121, 103
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
