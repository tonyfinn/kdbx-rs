use kdbx_rs;

fn main() -> Result<(), kdbx_rs::Error> {
    let args: Vec<String> = std::env::args().collect();
    let kdbx = kdbx_rs::open(&args[1])?;
    let key = kdbx_rs::CompositeKey::from_password(args.get(2).unwrap_or(&"kdbxrs".to_string()));
    let kdbx = kdbx.unlock(&key).map_err(|(e, _db)| e)?;
    let xml = kdbx_rs::xml::parse_xml(kdbx.xml_data());
    println!("{:#?}", xml);
    Ok(())
}
