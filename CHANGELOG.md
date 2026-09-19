# Changelog

All notable changes to OpenCryptoDetect are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-09-20

### Fixed
- Fixed broken badge URLs in README and updated repository clone instructions.
- Modernized type hints across benchmarking modules to use Python 3.10 union syntax.
- Optimized ChaCha20 quarter-round pattern rotation set lookup using frozenset constants.

### Added
- Added validation unit test for missing input file handling in `FileInspector`.
- Added models verification documentation and manifest checksum guide.

## [1.0.0] - 2026-09-19

### Added
- **Core CLI (`ocd`)**: Commands for `inspect`, `analyze`, `batch`, `benchmark`, and `ml` (`prepare-dataset`, `train`, `evaluate`, `export`).
- **Input Inspection**: Automatic format detection (ELF, Raw Binary, Intel HEX, Archives) and SHA-256 calculation.
- **Cross-Architecture Support**: ELF and raw binary disassembly supporting x86, x86-64, ARM, AArch64, MIPS, and RISC-V.
- **Binary Analysis Engine**: Function recovery via symbol tables, prologue scanning, basic block partitioning, and CFG loop discovery.
- **Deterministic Cryptographic Signatures**: Detection for AES (S-box, Inverse S-box, Rcon), SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-3, MD5, ChaCha20, HMAC, RSA, ECC (NIST P-256, Curve25519), and CRC32.
- **Heuristic Engine**: Operation densities (ARX, bitwise, shift/rotate), loop count, and experimental unknown crypto detection.
- **Machine Learning Classifier**: Multi-class Random Forest classifier trained across architectures with 48-dimensional feature vectors.
- **Evidence Fusion**: Calibrated Bayesian confidence scoring combining signatures, heuristics, and ML probabilities.
- **CBOM Generator**: CycloneDX 1.6 compliant Cryptographic Bill of Materials generation.
- **Reporting**: Structured versioned JSON and standalone responsive HTML reports.
- **Firmware Extractor**: Safe container unpacking with directory traversal and decompression bomb defenses.
- **Benchmarking Suite**: Reproducible evaluation suite measuring precision, recall, F1, FPR, and latency across approaches.
