# KDBX-rs

Library for reading and writing KDBX libraries from Rust


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
| Chacha20 Cipher  | No        | Yes          | Yes       | No          | No             |
| Salsa20 Cipher   | No        | Yes          | Yes       | Yes         | No             |
| TwoFish Cipher   | No        | Yes          | No        | Yes         | No             |
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