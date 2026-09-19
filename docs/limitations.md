# Limitations

While OpenCryptoDetect achieves high accuracy across standard architectures and compilers, users should understand the inherent boundaries of static cryptographic analysis.

## Technical Limitations

1. **Obfuscation & Virtualization**: Heavily obfuscated binaries (e.g., using control flow flattening, instruction virtualization, or opaque predicates) will disrupt basic block partitioning and feature calculation.
2. **Packing & Encryption**: Packed binaries (such as UPX or commercial protectors) conceal code and constants within compressed payloads. Analysts must unpack the outer envelope before scanning.
3. **Dynamic Code Generation (JIT)**: Dynamically generated machine code or self-modifying code cannot be evaluated statically.
4. **Stripped & Inlined Constants**: When aggressive compiler optimizations inline or fold mathematical constants (e.g. compile-time evaluation of hash rounds), signature detectors that look for individual constant words may miss them. The ML classifier and heuristic engine mitigate this by learning structural and ARX patterns.
5. **Non-Standard & Custom Cryptography**: Proprietary or non-standard ciphers lacking recognized constants are flagged as "Potential unknown cryptographic implementation (Experimental)" based on ARX density, but cannot be classified into named algorithms.
6. **False Positives in Error-Correction Code**: Algorithms such as CRC32, Reed-Solomon, or bit-interleaving matrix math share bitwise densities with symmetric ciphers. OpenCryptoDetect explicitly categorizes CRC32 as a non-cryptographic checksum to avoid false cryptographic assurances.
