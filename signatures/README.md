# OpenCryptoDetect Signature Database

This directory contains standalone signature definitions and pattern schemas for cryptographic primitive families:

- **`aes/`**: Rijndael S-box, Inverse S-box, Rcon key schedule constants, and T-tables.
- **`chacha/`**: Quarter-round ARX operation patterns and constant strings (`"expand 32-byte k"`).
- **`sha/`**: SHA-1, SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512), and Keccak SHA-3 round constants.
- **`rsa/`**: Big-integer modular arithmetic patterns and Fermat public exponent $F_4$ (`0x10001`).
- **`ecc/`**: Finite field prime parameters for NIST P-256 and Curve25519 / Ed25519.
- **`hmac/`**: Inner and outer pad constant patterns (`0x36` and `0x5C`).
