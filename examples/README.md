# OpenCryptoDetect Examples

This directory provides example detection artifacts and guidance for running sample analyses.

## Sample Files

- **`sample-output/crypto_sample.json`**: Full structured JSON output generated from analyzing a multi-primitive cryptographic binary (`crypto_x86_64.o`). Includes matched primitives (AES, SHA-256, MD5, ChaCha20, RSA), address localization offsets, and granular evidence lists.

## Generating Sample Reports

Run the analysis pipeline on any sample in `tests/fixtures/`:

```bash
# Generate JSON, CBOM, and HTML reports
ocd analyze tests/fixtures/crypto_x86_64.o --cbom --html --output-dir examples/sample-output/
```
