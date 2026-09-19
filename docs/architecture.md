# OpenCryptoDetect Architecture

OpenCryptoDetect (`ocd`) is structured as a modular pipeline designed to analyze executable binaries and firmware blobs without executing code or communicating with external networks.

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

## Core Modules

1. **Input Inspector (`input/`)**: Safely validates file size and entropy, discovers container format (ELF, Raw Binary, Intel HEX, Mach-O), identifies architecture and bitness, and extracts entry point metadata.
2. **Binary Analyzer (`binary/`)**: Adapts open-source disassembly engines (Capstone) to perform linear and recursive traversal, function discovery via symbol tables and architecture-specific prologue matching, basic block partitioning, and control flow graph (CFG) loop recovery.
3. **Feature Extraction (`features/`)**: Calculates a 30-feature numerical vector encompassing basic block topology, cyclomatic complexity, bitwise operation densities, shift/rotate ratios, memory load/store ratios, and cryptographic constant match frequencies.
4. **Detection Sub-Engines (`signatures/`, `heuristics/`, `ml/`)**:
   - **Signature Engine**: Deterministic pattern matching on Rijndael S-boxes, Keccak round constants, SHA-2 round arrays, MD5 sine tables, ChaCha20 expansion words, and elliptic curve primes.
   - **Heuristic Engine**: Structural analysis of addition-rotation-xor (ARX) instruction density and loop structures.
   - **ML Classifier**: Multi-class Random Forest model providing function-level classification probabilities.
5. **Evidence Fusion (`detection/`)**: Combines detector outputs probabilistically, maps findings to specific function addresses, applies NIST/security policies, and formats transparent explainability statements.
6. **Reporting (`cbom/`, `reporting/`)**: Emits human-readable terminal output, machine-readable JSON, CycloneDX 1.6 CBOM, and standalone HTML reports.
