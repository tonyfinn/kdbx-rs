# KDBX-rs

[Documentation][docs] | [Repository][repo] | [crates.io][package]

Library for reading and writing KDBX libraries from Rust. 

## Example code

Obtaining an entry from the password database:

```rust
use kdbx_rs::{self, CompositeKey, Error};
fn main() -> Result<(), Error> {
    let file_path = "./res/test_input/kdbx4-argon2d.kdbx";
    let kdbx = kdbx_rs::open(file_path)?;
    let key = CompositeKey::from_password("kdbxrs");
    let unlocked = kdbx.unlock(&key)?;

    let password = unlocked.find_entry(|e| e.url() == Some("https://example.com"))
        .unwrap()
        .password();

    println!(password);
    Ok(())
}
```

Generating a new password database:

```rust
let mut database = Database::default();
database.set_name("My First Database");
database.set_description("Created with kdbx-rs");

let mut entry = Entry::default();
entry.set_password("password1");
entry.set_url("https://example.com");
entry.set_username("User123");

database.add_entry(Entry);
```

Saving a database to a file

```rust
let mut database = Database::default();
let kdbx = Kdbx::from_database(database);
kdbx.set_key(CompositeKey::from_password("foo123"))?;

let mut file = File::create("/tmp/kdbx-rs-example.kdbx")?;
kdbx.write(&mut file)?;
```

## Comparison of Rust Keepass Libraries (as of May 2020)

|                  |[`kdbx-rs`]|[`keepass-rs`]| [`kdbx4`] |[`rust-kpdb`]|[`rust-keepass`]|
|------------------|-----------|--------------|-----------|-------------|----------------|
| License          | GPLv3+    | MIT          | MIT       | MIT/Apache  | ISC            |
| **Formats**      |           |              |           |             |                |
| .kdbx 4          | Yes       | Read only    | Read only | No          | No             |
| .kdbx 3          | Read only | Read only    | No        | Yes         | No             |
| .kdb             | No        | No           | No        | No          | Yes            |
| **Algorithms**                                                                         |
| *KDFs*                                                                                 |
| AES              | Yes       | Yes          | Yes       | Yes         | Yes            |
| Argon 2          | Yes       | Yes          | Yes       | No          | Yes            |
|*Database Ciphers*|           |              |           |             |                |
| AES              | Yes       | Yes          | Yes       | Yes         | Yes            |
| TwoFish          | Yes       | Yes          | No        | Yes         | No             |
| Chacha20         | Yes       | Yes          | Yes       | No          | No             |
| *Value Ciphers*  |           |              |           |             |                |
| Chacha20         | Yes       | Yes          | Yes       | No          | No             |
| Salsa20          | Yes       | Yes          | Yes       | Yes         | No             |
| **Features**     |           |              |           |             |                |
| Memory protection| No        | Yes          | No        | No          | Yes            |
| Keyfile auth     | Yes       | Yes          | Yes       | Yes         | Yes            |
| Windows  auth    | No        | No           | No        | No          | No             |
| KeepassXC OTPs   | No        | No           | No        | No          | No             |
| Custom fields    | Yes       | Yes          | Yes       | No          | No             |
| Entry History    | Yes       | No           | Yes       | Yes         | No             |


## License

This crate is licensed under GPLv3.0 or later, see [`LICENSE.txt`][license] for details.

[docs]: https://docs.rs/kdbx-rs/
[package]: https://crates.io/crates/kdbx-rs
[repo]: https://gitlab.com/tonyfinn/kdbx-rs
[license]: https://gitlab.com/tonyfinn/kdbx-rs/-/blob/master/LICENSE.txt
[`kdbx-rs`]: https://gitlab.com/tonyfinn/kdbx-rs
[`kdbx4`]: https://github.com/makovich/kdbx4
[`rust-kpdb`]: https://github.com/sru-systems/rust-kpdb
[`rust-keepass`]: https://github.com/raymontag/rust-keepass
[`keepass-rs`]: https://github.com/sseemayer/keepass-rs