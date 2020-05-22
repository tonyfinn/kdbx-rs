//! Prints the decrypted XML of a kdbx database
//!
//! Primarily for investigating the kdbx format. It takes the password
//! on the CLI, which is insecure

use kdbx_rs;

fn main() -> Result<(), kdbx_rs::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 1 {
        println!("Usage: kdbx-decrypt <path to kdbx file> <password>");
    }
    let kdbx = kdbx_rs::open(&args[1])?;
    let key = kdbx_rs::CompositeKey::from_password(args.get(2).unwrap_or(&"kdbxrs".to_string()));
    let kdbx = kdbx.unlock(&key)?;
    let data: Vec<u8> = kdbx.raw_xml().unwrap().iter().cloned().collect();
    println!("{}", String::from_utf8(data).unwrap());
    Ok(())
}
