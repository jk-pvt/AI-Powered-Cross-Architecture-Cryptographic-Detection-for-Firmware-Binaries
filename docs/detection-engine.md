# Cryptographic Detection Engine

The OpenCryptoDetect detection engine fuses three complementary methodologies: deterministic signatures, structural heuristics, and machine learning inference.

## 1. Deterministic Signature Matching
Deterministic signatures rely on mathematically invariant constants and tables required by cryptographic specifications:

- **AES**: Forward Rijndael S-box (`0x63, 0x7c, ...`), Inverse S-box (`0x52, 0x09, ...`), and key-schedule round constants $R_{con}$ (`0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36`).
- **SHA-256 / SHA-224**: 64 round constants $K[0..63]$ derived from the fractional parts of the cube roots of the first 64 prime numbers, plus initial IV constants.
- **SHA-512 / SHA-384**: 80 64-bit round constants $K[0..79]$ and initial 64-bit state words.
- **SHA-3 (Keccak)**: 24 64-bit round constants $RC[0..23]$.
- **MD5**: 64-element sine table $T[1..64]$ derived from $2^{32} \cdot |\sin(i)|$, and standard state IVs.
- **ChaCha20**: Constants `0x61707865, 0x3320646e, 0x79622d32, 0x6b206574` ("expand 32-byte k") and quarter-round ARX rotation sequences (16, 12, 8, 7).
- **HMAC**: Inner padding (`0x36363636`) and outer padding (`0x5c5c5c5c`) constant arithmetic operations.
- **RSA**: Standard Fermat public exponent $F_4 = 65537$ (`0x10001`).
- **ECC**: NIST P-256 prime field $p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$ and Curve25519 prime $2^{255} - 19$.
- **CRC32**: Generator polynomials `0xEDB88320` (IEEE 802.3 reflected) and `0x04C11DB7`. Flagged strictly as non-cryptographic checksum.

## 2. Structural Heuristics
Heuristics measure operational characteristics typical of cryptographic algorithms:
- **Bitwise density**: Proportion of bitwise instructions (`xor`, `and`, `or`, `not`).
- **Shift / rotate density**: Frequency of bitwise shifts (`shl`, `shr`, `sar`) and cyclic rotations (`rol`, `ror`).
- **ARX Density**: Combined density of Addition, Rotation, and XOR instructions.
- **CFG Topology**: Count of transformation loops, back-edges, and cyclomatic complexity.

## 3. Machine Learning Classification
A Random Forest classifier evaluated on cross-architecture binary samples operates on a 30-feature vector to classify functions into classes (`AES`, `SHA256`, `MD5`, `SHA1`, `ChaCha20`, `RSA`, `NonCrypto`).

## 4. Evidence Fusion & Explainability
Confidence scores are probabilistically fused:
- When a deterministic signature is present ($S_{sig} \ge 0.85$), the baseline is reinforced by corroborating heuristic density and ML classification probabilities.
- When no signature is present, ML classifications with probability $\ge 0.80$ confirmed by heuristic metrics ($\ge 0.30$) are promoted to findings.
- Every emitted finding enumerates exact addresses, matching tables, instruction metrics, and model probabilities.
