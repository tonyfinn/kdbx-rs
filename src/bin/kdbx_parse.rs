//! Prints out the kdbx-rs in memory representation
//! of a database
//!
//! Primarily for verifying kdbx-rs changes

fn main() -> Result<(), kdbx_rs::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.is_empty() {
        println!("Usage: kdbx-decrypt <path to kdbx file> <password>");
    }
    let kdbx = kdbx_rs::open(&args[1])?;
    let key = kdbx_rs::CompositeKey::from_password(args.get(2).unwrap_or(&"kdbxrs".to_string()));
    let kdbx = kdbx.unlock(&key)?;
    println!("{:#?}", kdbx.database());
    Ok(())
}
