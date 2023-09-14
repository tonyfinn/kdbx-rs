# Changelog

## 0.5.1

- Bump declared MSRV version to match actual version from `chrono`

## 0.5.0

- Dependency updates to remove time 0.1.0 
  [!6](https://gitlab.com/tonyfinn/kdbx-rs/-/merge_requests/6) - [Samuel
  Tardieu](https://gitlab.com/samueltardieu)
    - Note: MSRV raised to 0.57.0


## 0.4.0

- Add support for Argon2id
  [!1](https://gitlab.com/tonyfinn/kdbx-rs/-/merge_requests/1) - [Samuel
  Tardieu](https://gitlab.com/samueltardieu)
- Various other code cleanup

## 0.3.0

- Dependency updates

## 0.2.2

* Documentation additions/corrections

## 0.2.1

* Actually remove APIs listed as removed in 0.2.0
* Fix off by one error in datetime parsing of years

## 0.2.0

* Add support for writing protected values
* New APIs;
  * `Group::recursive_entries()` / `Group::recursive_entries_mut()` for iterating
    through all entries in a group and its child groups
  * `utils::NullStreamCipher` to parse/write XML files without inner encryption
  * `Group`
    * `recursive_entries()` / `recursive_entries_mut()` for iterating
      through all entries in a group and its child groups
    * `find_entry(Fn(&Entry) -> bool)` and `find_entry_mut(Fn(&Entry) -> bool)`
      for finding an entry recursively
    * `find_group(Fn(&Group) -> bool)` and `find_group_mut(Fn(&Group) -> bool)`
      for finding an entry recursively
  * Many group APIs are mirrored on `Database` for operating on the root group.
* Actually support AES KDF
* Read only support for KDBX 3.1
* Removed APIs
  * `kdbx_rs::xml::default_stream_cipher` - use `NullStreamCipher` or `InnerStreamCipherAlgorithm::stream_cipher()`
  * Struct fields on many database types are now hidden, use accessor fields instead

## 0.1.2

* Add support for reading KeepassXC OTP secrets (no code generation yet)
* Improve docs

## 0.1.1

Correct link to GPL

## 0.1.0

Initial release!
