# idris2-crypt: FFI Bindings to the `libxcrypt` Library used for Passphrase Hashing

This package provides bindings to the [libxcrypt](https://github.com/besser82/libxcrypt),
which provides strong algorithms for one-way hashing of passphrases.
It comes with a convenient and safe API on top of the FFI calls to
make sure that arguments to FFI functions have been properly
validated.

## Usage Examples

Typically, when you first hash a password for storing in a database,
you have to select a hashing method plus computational cost.
If uncertain, `YesCrypt` with a reasonably high cost of 8 or higher
seems to be a valid choice:

```idris
-- This will check that `pw` is a valid passphrase
-- (no longer than 512 bytes, including the terminal
-- `'\0'` character).
hashPW : String -> IO (Maybe Hash)
hashPW str = cryptMaybe YesCrypt 10 "my_s3cr3t_phr@s3"
```

Use `Text.Crypt.cryptcheck` for checking a passphrase against a hash.
