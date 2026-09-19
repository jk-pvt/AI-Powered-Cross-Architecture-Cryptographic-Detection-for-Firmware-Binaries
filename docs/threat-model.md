# Threat Model & Security Assumptions

OpenCryptoDetect is designed to analyze potentially hostile, malicious, or malformed firmware images and binaries.

## Threat Assumptions

1. **Hostile Inputs**: Firmware packages may contain intentionally crafted path traversal sequences (`../../`), symlink escapes, compressed decompression bombs (zip/tar bombs), truncated headers, or invalid ELF structures intended to exploit parsing vulnerabilities.
2. **Untrusted Code**: Any binary inside a firmware blob must be assumed to be untrusted. Code must never be executed or dynamically linked.
3. **Restricted Offline Operation**: Security analysts require tools that run locally on isolated air-gapped systems without leaking binary metadata or cryptographic findings over network connections.

## Implemented Security Defenses

- **Strict Non-Execution Policy**: OpenCryptoDetect employs static disassemblers (Capstone) and binary parsing libraries (pyelftools, lief) exclusively. No target binary or child process is ever executed.
- **Canonical Path Traversal Guards**: Path sanitization ensures that all extracted files reside strictly within controlled temporary sandboxes. Any attempt to write outside the sandbox triggers an immediate `SecurityViolationError`.
- **Archive Extraction Limits**: Hard limits on maximum file size (default 500 MB) and total extracted bytes (default 2 GB) prevent memory exhaustion and disk fill attacks.
- **Subprocess Isolation**: External helper processes execute with strict timeouts and resource limits.
- **Controlled Temporary Sandboxing**: Every unpacking run creates an isolated ephemeral directory with guaranteed cleanup upon termination or error.
- **Graceful Error Handling**: Parsing anomalies and malformed structures yield typed errors (`[INSPECT-001]`, `[ARCH-001]`) rather than unhandled Python exceptions.
