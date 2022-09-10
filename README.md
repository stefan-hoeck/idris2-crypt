# idris2-crypt: FFI Bindings to the `libxcrypt` Library used for Passphrase Hashing

This package provides bindings to the [libxcrypt](https://github.com/besser82/libxcrypt),
which provides strong algorithms for one-way hashing of passphrases.
It comes with a convenient and safe API on top of the FFI calls to
make sure that arguments to FFI functions have been properly
validated.
