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

    assert_eq!(db.major_version(), 4);
    assert_eq!(db.minor_version(), 0);
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
            variant: argon2::Variant::Argon2d,
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
            rounds: 20000,
            salt: vec![
                233, 186, 106, 9, 212, 114, 158, 27, 10, 91, 5, 111, 115, 106, 184, 135, 7, 58, 99,
                250, 194, 27, 26, 192, 114, 189, 192, 96, 127, 48, 201, 242
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

#[test]
fn load_kdbx31_aes256() {
    let mut file_path = PathBuf::new();
    file_path.push(env!("CARGO_MANIFEST_DIR"));
    file_path.push("res");
    file_path.push("test_input");
    file_path.push("kdbx31-aes256.kdbx");

    let file = fs::File::open(file_path).unwrap();

    let db = kdbx_rs::from_reader(file).unwrap();
    assert_eq!(db.major_version(), 3);
    assert_eq!(db.minor_version(), 1);
    assert_eq!(
        db.header().master_seed,
        [
            58, 27, 198, 230, 93, 182, 12, 4, 92, 244, 37, 71, 253, 32, 60, 26, 74, 85, 238, 187,
            132, 179, 254, 40, 243, 61, 127, 236, 181, 109, 80, 203
        ]
    );
    assert_eq!(
        db.header().encryption_iv,
        [162, 71, 175, 238, 61, 36, 113, 2, 152, 63, 98, 1, 132, 112, 96, 176]
    );
    assert_eq!(
        db.header().compression_type,
        kdbx_rs::binary::CompressionType::Gzip
    );
    assert_eq!(
        db.header().kdf_params,
        kdbx_rs::binary::KdfParams::Aes {
            rounds: 20000,
            salt: vec![
                36, 163, 46, 56, 122, 135, 118, 6, 177, 152, 12, 38, 88, 55, 178, 100, 99, 207, 62,
                101, 199, 191, 63, 72, 47, 153, 41, 120, 5, 104, 242, 247
            ]
        }
    );
}
