# KDBX File Format


## General

The KDBX format is really two formats. There is an outer container format which
is a binary format that is used for specifying the encryption settings, though
it is also extensible for plugins to store their own data as of kdbx 4. There is
also an inner XML format which stores the actual database, and is included
encrypted in the container format.



## Container format

* All multi-byte integer data in kdbx files is little endian.



### Prelude

A KDBX file starts with two magic numbers. The first of these is 0x9AA2D903 and is shared
by all KeePass files, both KDB and KDBX. The second is 0xB54BFB67. This one is shared by
all KDBX files. 

Next up there is the version number, which is stored as a unsigned 32 bit number. The high
two bytes represent the major version, while the low two bytes represent the minor version.
New minor versions should not make backwards incompatible changes, but new major versions may.



### Header

A KDBX header is stored in a TLV format (tag/length/value) format. The tag is a single
byte. The length field is a 32 bit unsigned int in KDBX 4 (16 bit in earlier versions).
Finally, the value follows for as many bytes as the length field declares. 

* Tag - 1 byte
* Length - 4 bytes (KDBX >= 4) / 2 bytes (KDBX < 4)
* Value

#### Variant Dictionary (KDBX v4)

The type used for key value pairs in KDBX is called a Variant Dictionary. It consists
of a sequence of fields in the format:

* Tag - 1 byte
* Name length - unsigned 32 bit integer
* Name - UTF-8 string
* Value length - unsigned 32 bit integer
* Value - length defined by length field, type defined by tag

Finally, after the last field, a single null byte indicates the end of the variant dictionary.

The following tags are currently used by KeePass:

* 0x04 - 32 bit signed integer
* 0x05 - 64 bit signed integer
* 0x08 - boolean value (1 = true, 0 = false)
* 0x0C - 32 bit unsigned integer
* 0x0D - 64 bit unsigned integer
* 0x18 - UTF-8 String
* 0x42 - Byte array

#### Outer header fields (as of KDBX 4.0)

* 0x02 - Cipher ID
  * Byte array representing a UUID used to lookup a cipher.
  * The cipher is used to encrypt/decrypt database data
  * Currently used ciphers are:
    * AES128 = 61ab05a1-9464-41c3-8d74-3a563df8dd35
    * AES256 = 31c1f2e6-bf71-4350-be58-05216afc5aff
    * TwoFish (KeePassXC) = ad68f29f-576f-4bb9-a36a-d47af965346c
    * Chacha20 = d6038a2b-8b6f-4cb5-a524-339a31dbb59a
* 0x03 - Compression Flags
  * Data used to determine compression options for the inner database
  * Currently a single byte, 0 = no compression, 1 = gzip
* 0x04 - Master Seed
  * Byte array used as a seed for key generation to prevent dictionary attacks
  * Currently always 32 bits
* 0x07 - Encryption IV
  * Initial value used to start off the encryption cipher
  * This is currently 16 bytes long
* 0x0B - KDF Parameters (KDBX 4+)
  * This is a variant dictionary
  * The key `$UUID` determines the algorithm being used to derive the key.
  * Like in the outer head, this is stored as a byte array
  * The following KDF values are used:
    * AES (kdbx 3.1) = c9d9f39a-628a-4460-bf74-0d08c18a4fea
    * AES (kdbx 4) = 7c02bb82-79a7-4ac0-927d-114a00648238
    * Note that it's possible for the KDBX 3.1 AES UUID to appear
      in a KDBX 4 file. 
    * Argon2 = ef636ddf-8c29-444b-91f7-a9a403e30a0c
  * AES Parameters
    * "R" - The number of rounds to use in the AES KDF
    * "S" - The seed/salt value to use in the AES KDF
  * Argon2 Parameters
    * "V" - The Argon2 version to use. Only 0x13 is widely supported
    * "P" - The number of parallel lanes to use in the Argon2 KDF
    * "M" - The amount of memory to use in the Argon2 KDF
    * "I" - The amount of iterations to use in the KDF.
    * "S" - The seed/salt value to use in the Argon2 KDF
* 0x0C - Public Custom Data
  * This field is reserved for plugins to store custom data.
  * The data will be a variant dictionary

One special header is 0x00, which represents the end of header. It should also be followed by
a length field with 0 length. This is unlike the variant dictionary format where the
data is terminated by a single null byte with no length field.

#### Legacy fields

* 0x01 - Comment
  * An unencrypted database description
* 0x05 - Transform Seed
  * Seed to use as an input to the AES KDF.
  * Replaced by KDF Parameters in new databases
* 0x06 - Transform rounds
  * Number of rounds to use in the AES KDF
  * Replaced by KDF Parameters in new databases
* 0x08 - Inner Stream Key
  * Key used to setup the random stream for protected values
  * Moved to inner header in new databases
* 0x09 - Stream Start Bytes
  * 32 bits that are also inserted at the start of the encrypted data
  * Formerly used to check the user entered the right key
  * Replaced by HMAC in KDBX 4
* 0x0A - Inner stream ID
  * Currently one byte
  * Algorithm used to encrypt internally protected data
  * See XML Format > Protected Values



### Encryption keys

The following type of keys are used for the container format.

#### Composite Key

The composite key is the collection of credentials the user has entered. For use in
encryption, it is converted to a single 256bit value. This is done by calculating
the SHA256 of each component present, concatenating them and then calculating the sha256
of that. The components are ordered as follows:

* Password
* Keyfile
* Windows user account

For example, for a password only key, this ends up being `sha256(sha256(password))`,
while a keyfile and password combination, this ends up being `sha256(sha256(password),sha256(keyfile))`.

#### Master Key

The master key is used as the basis of all other keys used for encryption. It is never
used directly in encryption. It is calculated by runing the configured KDF against the
processed composite key.

#### Cipher Key

The cipher key is used for encrypting/decrypting the database. It is calculated as 
`sha512(master seed, master key)`.

#### HMAC Key - KDBX 4+

The HMAC key is used to calculate per-block keys for verifying that data has not
been tampered with. It is calculated as `sha512(master seed, master key, 1)`. `1` is the
literal 8-bit value 1.

#### HMAC Block Key - KDBX 4+

A new key is generated to verify every block of data in the encrypted stream. It is
calculated as `sha512(block index, hmac key)`. The block index is a 64bit unsigned
integer. Header data is treated as having a block index of `u64::MAX`.



### Header verification

#### Header verification - KDBX 4

To verify the header data in KDBX 4, two checks are performed. The first is a
sha256 hash of the prelude and header. This is used to check against unintentional
corruption in transmission. The second is a HMAC calculated for the prelude and header.
The HMAC is calculated as HMAC-Sha256(prelude, header). The key used for this is
the HMAC block key for the block with index u64::MAX. 

#### Header verification - KDBX 3

To verify the header data in KDBX 3, one checks is performed. The inner XML format
has an element called `HeaderHash` which contains a sha256 of the header data. Since
this is in the encrypted data part, it is tamper-proof, but cannot be verified until
the database is decrypted.


### Encrypted data

The encrypted data is a sequence of blocks. The format of these blocks depend on
the version of KDBX in use. The file is terminated by a single block of 0 length.

#### Encrypted Data - KDBX 4

In KDBX 4, each of these block has the following format:

* HMAC-SHA256 (32 bytes)
* Ciphertext length (4 bytes)
* Ciphertext (variable length)

The HMAC is verified as `HMAC-Sha256(block index, ciphertext length, ciphertext)`.
The block index is the position of the block in the file.

#### Encrypted Data - KDBX 4

In KDBX 3, each of these blocks have the following format:

* SHA256 of plain text (32 bytes)
* Ciphertext length (4 bytes)
* Ciphertext (variable length)

The block is verified by decrypting the ciphertext, then calculating the sha256 hash.


### Inner header - KDBX 4

The first piece of encrypted data in KDBX 4 is the inner header. This follows the same TLV 
format as the outer header. It contains the following fields:

* 0x01 - Inner stream cipher ID
  * 1 byte
  * Cipher algorithm used for protected values (see XML Format > Protected Values for data)
* 0x02 - Inner stream cipher key
  * Length varies by inner cipher algorithm.
* 0x03 - Binary data
  * Contains 1 byte which is a bitset containing flags about the binary data, followed 
    by the binary data
  * Currently only the low bit of this bitset is used, which indicates the binary should be
    treated as a protected value
  * This header can occur multiple times



## XML Format

The rest of the data in the encrypted section is a XML document describing the
password database. To inspect some sample data, you can decrypt a kdbx database with
the official KeePass client's `Export > KeePass XML format` option, or the `kdbx-decrypt`
binary of `kdbx-rs`.

The following elements are included

* `KeePassFile`
    - Root node of the XML document. It contains two child elements `Meta` and `Root`.
* `Meta` 
    - Contains mostly key value metadata about the database. This keys are set by the
      official client and can be omitted. 
    - It also contains the `MemoryProtection` element which describes which elements 
      should be protected in memory.
    - It also contains the `CustomData` element. 
* `CustomData`
    * Used for clients/plugins other than the official client to store database wide information
    * Inside this contains a number of `Item` elements.
    * Each `Item` has two children, `Key` and `Value`. This is intended for database wide metadata
      from plugins or other consumers.
* `Root`
    - This contains a single `Group` element and is the root of the database hierarchy. 
* `Group` 
    - Represents a set of password entries. 
    - It has a `UUID` element to identify it
    - It has a `Name` field with a user chosen description.
    - It can contain child `Group` elements, or `Entry` elements for password entries
* `Entry`
    - Each element contains a single version of a single password entry.
    - It has a `UUID` element to identify it
    - It contains a number of `String` elements. These elements have `Key` and `Value`
      pairs, whose content are fields of the password entry. The `Value` field may
      optionally have a `Protected="true"` attribute to indicate it is a protected value (see below)
    - The following special keys have dedicated UI
      * `URL`
      * `UserName`
      * `Password`
      * `Notes`
      * `Title`
    - Other custom fields can be included as `String` elements, though the `CustomData` field
      was introduced as the recommended alternative for fields not provided by the official client
      as of KDBX 4. This has  the same format as in the `Meta` element.
    - It can contain a `History` element with past revisions. 
* `History`
    * The history element includes previous revisions of its parent entry
    * The UUID remains the same for historical entries.

### Encoded values

Certain data types are encoded in the XML document. The following transformations may be used:

* Datetimes (KDBX 4+): base64(seconds since 1/1/1 00:00:00) 
  * It's worth emphasising: Seconds since Year 1, not the unix epoch
* UUIDs: base64(uuid as byte array)

Note that KeePass's export as XML stores datetimes as ISO 8601 strings, which is not how they
are stored in actual KDBX 4 databases.

### Protected Values

Some data inside the database can be marked as protected. This performs two functions,
first of all it instructs clients to use memory protection on that field, and also additionally
encrypts the data inside the XML format, which leaves it still encrypted when the database is decrypted.

To perform this encryption, a stream cipher is used. The configuration values for this are stored 
in the inner header in KDBX 4, or the outer header in earlier versions. There are two configuration 
value. The first is the cipher ID, which is used to select which stream cipher to use.

Currently used Ciphers:

* 1 - ArcFour
* 2 - Salsa20
* 3 - Chacha20

The second is the inner stream key, which is used to setup the stream cipher. The size of this depends
on the algorithm in use.

Each protected value is decrypted by the stream cipher in the order they appear in the database. The
same cipher should be used to decrypt every value.




## References

* [Keepass file format explained](https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45) - Covers KDBX 2.x
    * Changes since that doc:
        * KDBX 3+ no longer include the block ID in the format
        * KDBX 4 supports many new stream ciphers.
        * KDBX 4 supports pluggable key derivation functions - the method described in the above 
          is valid for AES256 only. AES specific params have been moved into the KDF VariantDict
        * Header length fields have been increased from 2 bytes to 4 bytes
        * A sha256 field has been added to the end of the header for checking against data corruption
        * A HmacSha256 field has been added after the header for checking against data tampering. It
          also replaces the "start stream bytes" for verifying the user has entered the right key.
        * An inner header, with the same format as the outer header but encrypted has been added at the start
          of the file data, before any XML data
* [KDBX 4](https://keepass.info/help/kb/kdbx_4.html) - Covers changes from KDBX 3.1 to 4.0
    * One minor inaccuracy: 
        The doc describes HMAC keys as being calculated with SHA256. While HMAC-SHA256 is the algorithm
        used for calculating the HMACS, the key used is actually `SHA512(master seed, master key, 1)`
* [KeePassXC source code](https://github.com/keepassxreboot/keepassxc/tree/develop/src/format)
* [KeePass source code](https://keepass.info/download.html) ([unofficial github mirror](https://github.com/dlech/KeePass2.x))