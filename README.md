# KDBX-rs

Library for reading and writing KDBX libraries from Rust


## Comparison of Rust Keepass Libraries (as of May 2020)

|                  |[`kdbx-rs`]|[`kdbx4`]|[`rust-kpdb`]|[`keepass-rs`]|[`rust-keepass`]|
|------------------|-----------|---------|-------------|--------------|----------------|
| License          | GPLv3+    | MIT     | MIT/Apache  | MIT          | ISC            |
| KDF Support      | Argon2/AES| Argon2/AES | AES      | Argon2/AES   | AES            |
| Cipher support   | AES | AES/Chacha20  | AES/Salsa20 | AES/Chacha20 | AES            |
| .kdbx 4 support  | Yes       |Read only| No          | Read only    | No             |
| .kdbx 3 support  | No        | No      | Yes         | Read only    | No             |
| .kdb support     | No        | No      | No          | No           | Yes            |
| Memory protection| No        | No      | No          | Yes          | Yes            |
| Keyfile auth     | Yes       | Yes     | Yes         | Yes          | Yes            |
| Windows  auth    | No        | No      | No          | No           | No             |
| KeepassXC OTPs   | No        | No      | No          | No           | No             |
| Custom fields    | Yes       | Yes     | No          | Yes          | No             |
| Entry History    | Yes       | Yes     | Yes         | No           | No             |


[`kdbx-rs`]: https://gitlab.com/tonyfinn/kdbx-rs
[`kdbx4`]: https://github.com/makovich/kdbx4
[`rust-kpdb`]: https://github.com/sru-systems/rust-kpdb
[`rust-keepass`]: https://github.com/raymontag/rust-keepass
[`keepass-rs`]: https://github.com/sseemayer/keepass-rs