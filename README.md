# OpenCryptoDetect (`ocd`)

> **Open-source cross-architecture cryptographic primitive detection for firmware binaries.**

[![CI](https://github.com/opencryptodetect/opencryptodetect/actions/workflows/ci.yml/badge.svg)](https://github.com/opencryptodetect/opencryptodetect/actions/workflows/ci.yml)
[![Tests](https://github.com/opencryptodetect/opencryptodetect/actions/workflows/tests.yml/badge.svg)](https://github.com/opencryptodetect/opencryptodetect/actions/workflows/tests.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

---

## 1. Problem Statement

Firmware binaries, IoT images, and embedded devices frequently incorporate cryptographic routines—often using deprecated, broken algorithms (e.g., MD5, SHA-1, DES) or insecure configurations without maintaining software bills of materials. Traditional binary analysis tools either require heavy proprietary reverse-engineering suites (IDA Pro, Ghidra) or perform crude regex string searches that miss stripped implementations and provide zero explainability.

**OpenCryptoDetect** is a local, fast, cross-architecture command-line tool that statically detects, localizes to exact addresses, classifies, and explains cryptographic primitives across firmware and binary images. It combines deterministic signature tables, structural heuristics, and machine learning into a unified evidence fusion pipeline.

---

## 2. Architecture

```
                    ┌────────────────────────────────┐
                    │ Input Binary / Firmware Image  │
                    └───────────────┬────────────────┘
                                    │
                            [File Inspector]
                   (SHA-256, Magic, Format, Arch, Endian)
                                    │
                           [Firmware Extractor]
                (Safe Extraction, Sandbox, Path Traversal Guard)
                                    │
                            [Binary Analyzer]
            (PyElfTools / Capstone: Sections, Functions, CFG, Constants)
                                    │
                      [Function Feature Extractor]
           (Opcode stats, Bitwise density, ARX patterns, CFG metrics)
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
[Signature Engine]         [Heuristic Engine]          [ML Classifier]
- S-boxes & T-tables       - XOR/Shift/Rotate density  - Random Forest
- Hash constant arrays     - Loop & ARX structures     - Class probabilities
- Curve parameters         - Modular arithmetic        - Feature schema v1.0
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    │
                            [Evidence Fusion]
             (Bayesian / Evidentiary Fusion + Address Localization)
                                    │
                        [Library Fingerprinter]
                    (OpenSSL, mbedTLS, wolfSSL, etc.)
                                    │
                        [Weak Algorithm Policy]
                     (MD5, SHA-1, DES, CRC32 Checksum)
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
  [CLI Terminal]              [CBOM Output]             [HTML Report]
Rich tables & summaries   CycloneDX 1.6 Cryptography   Self-contained visual report
```

---

## 3. Key Features

- **Multi-Engine Fusion**: Integrates deterministic signatures, structural heuristics (ARX operation density, CFG loops), and multi-class machine learning classifiers.
- **Cross-Architecture Support**: Disassembles and evaluates ARM (32-bit/Thumb), AArch64, x86, x86-64, MIPS, and RISC-V.
- **Explainable Detections**: Every finding details *why* it was detected, specifying addresses, matched tables, loop counts, and model probabilities.
- **Cryptographic Bill of Materials (CBOM)**: Automatically generates CycloneDX 1.6-compliant CBOMs cataloging algorithms, locations, and security statuses.
- **Standalone HTML & JSON Reports**: Produces zero-dependency interactive HTML reports and structured versioned JSON reports.
- **Security Hardened**: Operates strictly via static inspection; never executes target code; enforces strict directory traversal guards and archive size limits.
- **Zero Cloud Dependencies**: Runs 100% offline without uploading firmware, code, or telemetry.

---

## 4. Supported Formats & Architectures

### Input Formats
- **ELF** (32-bit & 64-bit, Little and Big Endian)
- **Raw Binary Blobs** (Flash ROM images, bootloaders)
- **Mach-O** (macOS, iOS binaries)
- **PE / COFF** (Windows binaries)
- **Intel HEX** records
- **Containers & Archives** (ZIP, TAR, CPIO, GZIP)

### Target Architectures
- **x86-64** (AMD64)
- **AArch64** (ARM 64-bit)
- **ARM** (ARMv7, Thumb, Cortex-M)
- **x86** (IA-32)
- **MIPS** (MIPS32 / MIPS64)
- **RISC-V** (RV32 / RV64)

---

## 5. Supported Cryptographic Algorithms

| Category | Algorithms | Security Status |
| :--- | :--- | :--- |
| **Symmetric Block Ciphers** | AES (128/192/256), DES, 3DES | AES: Secure; DES/3DES: Deprecated/Insecure |
| **Hash Functions** | SHA-256, SHA-224, SHA-512, SHA-384, SHA-3 (Keccak), MD5, SHA-1 | SHA-2/3: Secure; MD5/SHA-1: Weak/Deprecated |
| **Stream Ciphers & MACs** | ChaCha20, Poly1305, HMAC | Secure |
| **Asymmetric & Signatures** | RSA, ECDSA (NIST P-256), Ed25519 (Curve25519) | Secure |
| **Checksums** | CRC32 (Reflected & Standard) | Non-Cryptographic Checksum |

---

## 6. Installation

```bash
# Clone the repository
git clone https://github.com/opencryptodetect/opencryptodetect.git
cd opencryptodetect

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with ML and analysis dependencies
pip install -e ".[all]"
```

Verify installation:
```bash
ocd --version
ocd --help
```

---

## 7. Quick Start

### 1. Inspect a Binary
Inspect container format, architecture, hashes, and entry points:
```bash
ocd inspect router.bin
```

### 2. Full Cryptographic Analysis
Analyze binary and display detections in the terminal:
```bash
ocd analyze router.bin
```

### 3. Generate Reports (JSON, CBOM, HTML)
```bash
ocd analyze router.bin --cbom --html --json
```

### 4. Batch Analysis
Analyze an entire directory of firmware binaries:
```bash
ocd batch ./firmware_dumps/ --output-dir ./reports --cbom --html
```

---

## 8. Sample Terminal Output

```
OpenCryptoDetect v1.0.0

Firmware
────────────────────────────────────────
File:          crypto_x86_64.o
SHA-256:       9d5a4a2ce384761417fdcc18207b9d58414610b49f7f95f2df17192c32676979
Size:          2.0 KB
Architecture:  X86_64 (64-bit, little)

Analysis
────────────────────────────────────────
Functions:     5
Analyzed:      5
Duration:      0.841s

Cryptographic primitives
────────────────────────────────────────
  Algorithm    Location    Confidence    Methods                 
  ChaCha20     0x30        0.93          heuristic,signature     
  CRC32        0x60        0.95          heuristic,signature     
  AES          0x10        0.97          heuristic,ml,signature  

Evidence
────────────────────────────────────────
ChaCha20 at 0x30:
  • ChaCha20 expansion constant word matched in operands
  • Quarter-round ARX rotation set (16, 12, 8, 7) present
  • High ARX operation density: 88.2%
  • Elevated bitwise operation density: 47.1%
CRC32 at 0x60:
  • CRC32 generator polynomial 0xEDB88320 (IEEE 802.3 reflected) matched
  • Function contains 1 transformation loops
AES at 0x10:
  • AES Rijndael Forward S-box (256 bytes full match) in section '.rodata'
  • High ARX operation density: 50.0%
  • Elevated bitwise operation density: 50.0%
  • ML classifier predicted AES with probability 0.58

Reports
────────────────────────────────────────
JSON: /path/to/crypto_x86_64.ocd.json
CBOM: /path/to/crypto_x86_64.cbom.json
HTML: /path/to/crypto_x86_64.ocd.html
```

---

## 9. Benchmarks & Empirical Evaluation

OpenCryptoDetect includes an automated benchmarking suite (`ocd benchmark`). The numbers below are **empirically measured** on 169 compiled functions across x86-64, AArch64, and ARM architectures across optimization levels `-O0` through `-Os`:

| Approach | Precision | Recall | F1-Score | False Positive Rate | Avg Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Signature Only** | 0.877 | 0.573 | 0.693 | 0.222 | 0.01 ms |
| **Heuristic Only** | 0.931 | 0.218 | 0.353 | 0.044 | 0.01 ms |
| **ML Only** | 1.000 | 0.782 | 0.878 | 0.000 | 14.79 ms |
| **Hybrid Engine** | 0.882 | 0.726 | 0.796 | 0.267 | 14.51 ms |

Run the benchmark suite locally:
```bash
ocd benchmark
```

---

## 10. Machine Learning Workflow

```bash
# 1. Compile multi-architecture dataset samples
ocd ml prepare-dataset -n 200

# 2. Train Random Forest model
ocd ml train --algorithm rf

# 3. Evaluate multi-class metrics
ocd ml evaluate

# 4. Export production bundle with manifest & checksum
ocd ml export
```

A reproducible Google Colab workflow is available at [`notebooks/train_crypto_classifier.ipynb`](notebooks/train_crypto_classifier.ipynb).

---

## 11. Security & Threat Model

OpenCryptoDetect is built to safely inspect untrusted firmware images:
- **Zero Execution**: Target binaries are never run or dynamically loaded.
- **Traversal Defense**: Archive unpacking rejects path traversal sequences (`../`, absolute paths).
- **Resource Protections**: Enforces maximum file size limits (500 MB) and decompression byte limits (2 GB).
- See [`SECURITY.md`](SECURITY.md) and [`docs/threat-model.md`](docs/threat-model.md) for full details.

---

## 12. Documentation

- [Architecture Overview](docs/architecture.md)
- [Detection Engine & Fusion](docs/detection-engine.md)
- [Supported Formats](docs/supported-formats.md)
- [Supported Algorithms & Policy](docs/supported-algorithms.md)
- [Cryptographic Bill of Materials (CBOM)](docs/cbom.md)
- [Machine Learning Methodology](docs/ml.md)
- [Benchmarking Methodology](docs/benchmarking.md)
- [Threat Model](docs/threat-model.md)
- [Limitations](docs/limitations.md)

---

## 13. License

OpenCryptoDetect is licensed under the [Apache License, Version 2.0](LICENSE).
