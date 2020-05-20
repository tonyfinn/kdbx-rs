use kdbx_rs;

fn main() -> Result<(), kdbx_rs::Error> {
    let args: Vec<String> = std::env::args().collect();
    let db = kdbx_rs::open(&args[1])?;
    let key = kdbx_rs::CompositeKey::from_password(args.get(2).unwrap_or(&"kdbxrs".to_string()));
    let db = db.unlock(&key).map_err(|(e, _db)| e)?;
    let data: Vec<u8> = db.xml_data().iter().cloned().collect();
    println!("{}", String::from_utf8(data).unwrap());
    Ok(())
}
