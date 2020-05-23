# Changelog

## 0.2.0

* Add support for writing protected values
* New APIs;
  * `Group::recursive_entries()` / `Group::recursive_entries_mut()` for iterating
    through all entries in a group and its child groups
  * `utils::NullStreamCipher` to parse/write XML files without inner encryption
* Removed APIs
  * `kdbx_rs::xml::default_stream_cipher` - use `NullStreamCipher` or `InnerStreamCipherAlgorithm::stream_cipher()`

## 0.1.2

* Add support for reading KeepassXC OTP secrets (no code generation yet)
* Improve docs

## 0.1.1

Correct link to GPL

## 0.1.0

Initial release!