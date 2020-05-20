use kdbx_rs;

fn print_kdf(params: &kdbx_rs::binary::KdfParams) {
    use kdbx_rs::binary::KdfParams as p;
    match params {
        p::Argon2 {
            salt,
            iterations,
            memory_bytes,
            version,
            lanes,
        } => {
            println!("KDF: Argon2");
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
    let kdbx = kdbx_rs::open(&args[1])?;
    let header = kdbx.header();
    println!("Cipher: {:?}", header.cipher);
    println!("Compression: {:?}", header.compression_type);
    print_kdf(&header.kdf_params);
    println!("Master Seed: {:?}", header.master_seed);
    println!("Encryption IV: {:?}", header.encryption_iv);
    println!("Other headers: {:?}", header.other_headers);
    Ok(())
}
