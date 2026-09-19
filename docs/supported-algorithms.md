# Supported Cryptographic Algorithms & Security Policies

OpenCryptoDetect classifies cryptographic primitives and provides security classifications according to current NIST recommendations.

## Algorithm Matrix

| Algorithm | Primitive Type | Security Status | NIST Status | Primary Signatures / Heuristics |
| :--- | :--- | :--- | :--- | :--- |
| **AES** (128/192/256) | Block Cipher | Secure | Approved (FIPS 197) | Forward/Inverse S-boxes, Rcon round constants, T-tables. |
| **SHA-256 / SHA-224** | Hash Digest | Secure | Approved (FIPS 180-4) | 64-word K constant array, initial state IVs, Sigma functions. |
| **SHA-512 / SHA-384** | Hash Digest | Secure | Approved (FIPS 180-4) | 80-word 64-bit K array, 64-bit state IVs. |
| **SHA-3 (Keccak)** | Hash Digest | Secure | Approved (FIPS 202) | 24-word 64-bit Keccak round constants $RC[0..23]$. |
| **ChaCha20** | Stream Cipher | Secure | Approved (RFC 8439) | "expand 32-byte k" string, quarter-round ARX rotation sets (16, 12, 8, 7). |
| **Poly1305** | MAC | Secure | Approved (RFC 8439) | Clamping masks, modular prime $2^{130}-5$ reduction patterns. |
| **HMAC** | MAC | Secure | Approved (FIPS 198-1) | Inner pad (`0x36`) and outer pad (`0x5c`) constants. |
| **RSA** | Asymmetric | Secure (>= 2048-bit) | Approved (FIPS 186-5) | Public exponent 65537 (`0x10001`), Montgomery reduction loops. |
| **ECDSA** | Signature | Secure | Approved (FIPS 186-5) | NIST P-256 ($secp256r1$) curve prime field and base point constants. |
| **Ed25519** | Signature | Secure | Approved (RFC 8032) | Curve25519 prime $2^{255}-19$ field constants. |
| **MD5** | Hash Digest | **Weak** | **Disallowed** | 64-entry per-round sine table $T[1..64]$, standard state IVs. Vulnerable to collision attacks. |
| **SHA-1** | Hash Digest | **Deprecated** | **Deprecated** | Round constants $K_0..K_3$. Deprecated for digital signatures. |
| **DES** | Block Cipher | **Insecure** | **Disallowed** | Initial Permutation, 56-bit key schedule, DES S-boxes $S_1..S_8$. |
| **3DES** | Block Cipher | **Deprecated** | **Disallowed** | Triple-DES key schedule. Retired due to Sweet32 64-bit block size attacks. |
| **CRC32** | Checksum | **Non-Cryptographic**| **N/A** | Reflected polynomial `0xEDB88320`, standard `0x04C11DB7`. Flagged strictly as error-detection checksum. |
