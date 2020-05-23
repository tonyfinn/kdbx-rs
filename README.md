# KDBX-rs

Library for reading and writing KDBX libraries from Rust

## Example code

Obtaining the first password in the password database:

```rust
use kdbx_rs::{self, CompositeKey, Error};
fn main() -> Result<(), Error> {
    let file_path = "./res/kdbx4-argon2.kdbx";
    let kdbx = kdbx_rs::open(file_path)?;
    let key = CompositeKey::from_password("kdbxrs");
    let unlocked = kdbx.unlock(&key)?;

    println!(unlocked.root().entries[0].password())
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
let kdbx = Kdbx::from_database(database)?;
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
| .kdbx 3          | No        | Read only    | No        | Yes         | No             |
| .kdb             | No        | No           | No        | No          | Yes            |
| **Algorithms**   |           |              |           |             |                |
| AES KDF          | Yes       | Yes          | Yes       | Yes         | Yes            |
| Argon 2 KDF      | Yes       | Yes          | Yes       | No          | Yes            |
| AES Cipher       | Yes       | Yes          | Yes       | Yes         | Yes            |
| TwoFish Cipher   | Yes       | Yes          | No        | Yes         | No             |
| Chacha20 Cipher  | No        | Yes          | Yes       | No          | No             |
| Salsa20 Cipher   | No        | Yes          | Yes       | Yes         | No             |
| **Features**     |           |              |           |             |                |
| Memory protection| No        | Yes          | No        | No          | Yes            |
| Keyfile auth     | Yes       | Yes          | Yes       | Yes         | Yes            |
| Windows  auth    | No        | No           | No        | No          | No             |
| KeepassXC OTPs   | No        | No           | No        | No          | No             |
| Custom fields    | Yes       | Yes          | Yes       | No          | No             |
| Entry History    | Yes       | No           | Yes       | Yes         | No             |


[`kdbx-rs`]: https://gitlab.com/tonyfinn/kdbx-rs
[`kdbx4`]: https://github.com/makovich/kdbx4
[`rust-kpdb`]: https://github.com/sru-systems/rust-kpdb
[`rust-keepass`]: https://github.com/raymontag/rust-keepass
[`keepass-rs`]: https://github.com/sseemayer/keepass-rs