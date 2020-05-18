# KDBX File Format

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
        used for calculating the HMACS, the key used is actually SHA512(master seed, master key, 1)