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
            207, 62, 53, 60, 198, 212, 109, 146, 204, 133, 64, 114, 244, 214, 170, 180, 81, 74,
            233, 18, 139, 11, 1, 2, 141, 45, 120, 151, 48, 36, 249, 63
        ]
    );
    assert_eq!(
        db.header().encryption_iv,
        vec![69, 186, 132, 133, 27, 44, 62, 50, 166, 98, 75, 127, 168, 82, 62, 81]
    );
    assert_eq!(
        db.header().kdf_params,
        crypto::KdfOptions::Argon2 {
            iterations: 26,
            lanes: 2,
            memory_bytes: 65536 * 1024,
            version: 0x13,
            salt: vec![
                138, 66, 92, 254, 173, 216, 129, 158, 145, 34, 248, 226, 224, 114, 148, 9, 225, 12,
                0, 104, 208, 126, 97, 222, 199, 146, 1, 20, 50, 190, 183, 29
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
