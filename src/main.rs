use kdbx_rs::crypto;
use kdbx_rs::database;
use std::fs::File;
use std::io;
use std::io::Write;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("Error opening database file: {0}")]
    Io(#[from] io::Error),
    #[error("Could not open database: {0}")]
    Open(#[from] database::OpenError),
    #[error("Could not unlock database: {0}")]
    Unlock(#[from] database::UnlockError),
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let file = File::open(&args[1])?;
    let db = database::read(file)?;
    let key = crypto::CompositeKey::pwonly("kdbxrs");
    let db = db.unlock(key).map_err(|(e, _db)| e)?;
    let mut output_file = File::create("decrypted-db.xml")?;
    output_file.write_all(&db.decrypted_data())?;
    output_file.flush()?;
    Ok(())
}
