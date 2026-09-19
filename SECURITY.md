# Security Policy

## Reporting Security Vulnerabilities

If you discover a vulnerability or security flaw in OpenCryptoDetect, please report it responsibly by contacting the maintainers directly or opening a private GitHub Security Advisory. Do **not** disclose security vulnerabilities via public GitHub issues.

We aim to acknowledge receipt of all vulnerability reports within 48 hours and provide patch updates through private security advisories.

## Threat Model and Hostile Firmware Handling

OpenCryptoDetect treats all scanned binaries and firmware files as untrusted, potentially hostile input.

### Guarantees:
1. **No Execution:** OpenCryptoDetect is a pure static analysis and inspection tool. It **never** executes, runs, or dynamically loads firmware binaries or extracted files under any circumstances.
2. **Path Traversal Defense:** All archive and container extraction (ZIP, TAR, CPIO) enforces strict canonical path validation. Directory traversal sequences (`../`, absolute paths, symlink escapes) are rejected with `SecurityViolationError`.
3. **Decompression Bomb Defense:** Archive unpackers enforce strict cumulative byte limits (default 2 GB) and maximum file size limits (default 500 MB) to prevent denial-of-service via compression bombs.
4. **Temporary Sandboxing:** Extracted components are written strictly to temporary sandboxed directories with guaranteed cleanup on completion or error.
5. **No Cloud Dependencies:** OpenCryptoDetect operates completely offline and never uploads binaries, hashes, or analysis telemetry to remote endpoints.
