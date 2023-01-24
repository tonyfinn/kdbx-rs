//! Prints the parsed header of a kdbx database
//!
//! Primarily for investigating the kdbx format.

fn print_kdf(params: &kdbx_rs::binary::KdfParams) {
    use kdbx_rs::binary::KdfParams as p;
    match params {
        p::Argon2 {
            variant,
            salt,
            iterations,
            memory_bytes,
            version,
            lanes,
        } => {
            println!("KDF: Argon2");
            println!("\tVariant: {:?}", variant);
            println!("\tVersion: {}", version);
            println!("\tLanes: {}", lanes);
            println!(
                "\tMemory: {} bytes ({}kib)",
                memory_bytes,
                memory_bytes / 1024
            );
            println!("\tIterations: {}", iterations);
            println!("\tSalt: {:?}", salt);
        }
        p::Aes { rounds, salt } => {
            println!("KDF: AES");
            println!("\tRounds: {}", rounds);
            println!("\tSalt: {:?}", salt);
        }
        p::Unknown { uuid, params } => {
            println!("KDF: Unknown ({})", uuid);
            println!("{:?}", params);
        }
    }
}

fn main() -> Result<(), kdbx_rs::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.is_empty() {
        println!("Usage: kdbx-dump-header <path to kdbx file>");
    }
    let kdbx = kdbx_rs::open(&args[1])?;
    let header = kdbx.header();
    println!("Version: {}.{}", kdbx.major_version(), kdbx.minor_version());
    println!("Cipher: {:?}", header.cipher);
    println!("Compression: {:?}", header.compression_type);
    print_kdf(&header.kdf_params);
    println!("Master Seed: {:?}", header.master_seed);
    println!("Encryption IV: {:?}", header.encryption_iv);
    println!("Other headers: {:?}", header.other_headers);
    Ok(())
}
