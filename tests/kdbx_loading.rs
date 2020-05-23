use kdbx_rs;
use std::fs;
use std::path::PathBuf;

#[test]
fn load_kdbx4_argon2() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("test_input");
    file_path.push("kdbx4-argon2.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();

    assert_eq!(db.header().cipher, kdbx_rs::binary::Cipher::Aes256);
    assert_eq!(
        db.header().compression_type,
        kdbx_rs::binary::CompressionType::Gzip
    );
    assert_eq!(db.header().other_headers, Vec::new());
    assert_eq!(
        db.header().master_seed,
        vec![
            3, 103, 229, 54, 58, 152, 193, 13, 47, 191, 142, 159, 176, 102, 248, 87, 70, 86, 158,
            9, 98, 102, 81, 188, 99, 127, 207, 152, 122, 169, 242, 255
        ],
    );
    assert_eq!(
        db.header().encryption_iv,
        vec![175, 17, 232, 66, 142, 50, 3, 0, 166, 208, 221, 113, 73, 238, 22, 115],
    );
    assert_eq!(
        db.header().kdf_params,
        kdbx_rs::binary::KdfParams::Argon2 {
            iterations: 2,
            lanes: 2,
            memory_bytes: 65536 * 1024,
            version: 0x13,
            salt: vec![
                29, 167, 148, 98, 171, 253, 170, 215, 33, 234, 2, 203, 36, 205, 84, 194, 174, 203,
                92, 231, 23, 128, 183, 202, 99, 7, 121, 253, 51, 26, 212, 102
            ],
        }
    );
}

#[test]
fn load_kdbx4_aes256() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("test_input");
    file_path.push("kdbx4-aes256.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();
    assert_eq!(
        db.header().kdf_params,
        kdbx_rs::binary::KdfParams::Aes {
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
    file_path.push("test_input");
    file_path.push("kdbx4-aes256-legacy.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();
    assert_eq!(
        db.header().kdf_params,
        kdbx_rs::binary::KdfParams::Aes {
            rounds: 31130267,
            salt: vec![
                180, 76, 210, 106, 16, 174, 0, 214, 176, 158, 130, 118, 83, 207, 237, 52, 172, 84,
                127, 37, 150, 154, 40, 152, 167, 205, 218, 233, 142, 149, 155, 224
            ]
        }
    );
}
