# Cryptographic Bill of Materials (CBOM)

OpenCryptoDetect implements CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) generation.

## CBOM Overview
A Cryptographic Bill of Materials catalogs all cryptographic assets, primitives, algorithms, key strengths, implementations, and locations within a firmware image or software binary. This enables automated post-quantum readiness assessments and compliance audits.

## CycloneDX 1.6 Cryptographic Asset Schema
Under the CycloneDX 1.6 specification, each detected primitive is represented as a `cryptographic-asset` component with a `cryptoProperties` block:

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto-asset-1",
  "name": "AES",
  "version": "embedded-implementation",
  "description": "Detected AES at address 0x10 (aes_sub_byte)",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "block-cipher",
      "executionEnvironment": "software-plain-binary",
      "implementationPlatform": "x86_64",
      "cryptoFunctions": ["AES"]
    },
    "detectionContext": {
      "detectionMethods": ["heuristic", "ml", "signature"],
      "confidence": 0.97,
      "location": {
        "address": "0x10",
        "symbol": "aes_sub_byte",
        "file": "firmware.bin"
      },
      "evidence": [
        "AES Rijndael Forward S-box (256 bytes full match) in section '.rodata'",
        "High ARX operation density: 50.0%",
        "ML classifier predicted AES with probability 0.58"
      ]
    },
    "securityStatus": {
      "classification": "secure",
      "advisoryNote": "FIPS 197 approved symmetric block cipher."
    }
  }
}
```

## CLI Usage
Generate a CycloneDX CBOM:
```bash
ocd analyze firmware.bin --cbom -o cbom.json
```
