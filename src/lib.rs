#![deny(missing_docs)]

//! Module to read and write KDBX (Keepass 2) database files.
//!
//! The main types in this crate are:
//!
//! * [`Database`] which represents a password database
//! * [`Kdbx`] which represents a database file, including encryption options
//!
//! # Opening a database
//!
//! Databases can be read with the [`kdbx_rs::open`] function. This provides
//! access to header information. It can then be unlocked by providing a [`CompositeKey`]
//! to the [`Kdbx.unlock`] method to access any encrypted data.
//!
//! ```
//! # fn main() -> Result<(), kdbx_rs::Error> {
//! use kdbx_rs::CompositeKey;
//!
//! # let file_path = "./res/test_input/kdbx4-argon2.kdbx";
//! let kdbx = kdbx_rs::open(file_path)?;
//! let key = CompositeKey::from_password("kdbxrs");
//! let unlocked = kdbx.unlock(&key)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Generating a new password database
//!
//! A database can be created in memory by using the [`Database::default()`]
//! method. This will create an empty database which you can then populate.
//!
//! ```
//! use kdbx_rs::database::{Database, Entry};
//!
//! let mut database = Database::default();
//! database.set_name("My First Database");
//! database.set_description("Created with kdbx-rs");
//!
//! let mut entry = Entry::default();
//! entry.set_password("password1");
//! entry.set_url("https://example.com");
//! entry.set_username("User123");
//!
//! database.add_entry(entry);
//! ```
//!
//! # Saving a database to a file
//!
//! To save a database to a file, you first need to create
//! a [`Kdbx`] instance from that database, for example with
//! [`Kdbx::from_database`]. This will generate encryption options using
//! salts and random values from the OS's secure RNG. These can be customised,
//! or you can save the database as is.
//!
//! Before saving a new database for the first time, you'll need to set the user
//! credentials to save your database. This can be done with [`Kdbx.set_key`].
//! Provide a [`CompositeKey`] instance, which can be created the same way as for
//! unlocking database. This will then be used to generate the remaining keys
//! allowing you to save the database using [`Kdbx.write()`]
//!
//! ```rust
//! use kdbx_rs::{CompositeKey, Kdbx};
//! # use kdbx_rs::Database;
//! # use std::fs::File;
//!
//! # fn main() -> Result<(), kdbx_rs::Error> {
//! # let mut database = Database::default();
//! # let file_path = "/tmp/kdbx-rs-example.kdbx";
//! let mut kdbx = Kdbx::from_database(database);
//! kdbx.set_key(CompositeKey::from_password("foo123"))?;
//!
//! let mut file = File::create(file_path).unwrap();
//! kdbx.write(&mut file)?;
//! # Ok(())
//! # }
//! ```
//! Alternatively, [`kdbx_rs::from_reader`] can be used to open a database
//! from a non file source (such as in-memory or a network stream)
//!
//! [`CompositeKey`]: crate::CompositeKey
//! [`Database`]: crate::Database
//! [`Database::default()`]: crate::Database#method.default
//! [`kdbx_rs::from_reader`]: crate::from_reader
//! [`kdbx_rs::open`]: crate::open
//! [`Kdbx`]: crate::Kdbx
//! [`Kdbx.from_database`]: crate::Kdbx#method.from_database
//! [`Kdbx.set_key`]: crate::Kdbx#method.set_key
//! [`Kdbx.unlock`]: crate::Kdbx#method.unlock
//! [`Kdbx.write`]: crate::Kdbx#method.write

pub mod binary;
mod crypto;
pub mod errors;
mod stream;
mod types;
mod utils;
pub mod xml;

pub use crate::types::Database;
/// Password database datatypes
pub mod database {
    pub use crate::types::*;
}
pub use binary::{from_reader, open, Kdbx};
pub use crypto::CompositeKey;
pub use errors::Error;
