# Contributing to OpenCryptoDetect

Thank you for your interest in contributing to **OpenCryptoDetect (`ocd`)**! We welcome contributions from reverse engineers, cryptographers, ML researchers, and developers.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/opencryptodetect/opencryptodetect.git
   cd opencryptodetect
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install editable dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -e ".[all,dev]"
   ```

4. **Verify test suite:**
   ```bash
   pytest -v
   ```

## Adding New Cryptographic Signatures

1. Place exact mathematical constant arrays, S-boxes, or initialization vectors in `src/opencryptodetect/signatures/constants.py`.
2. Add pattern matchers or structural heuristics to `src/opencryptodetect/signatures/patterns.py`.
3. Register the detection logic in `src/opencryptodetect/signatures/engine.py`.
4. Ensure every finding provides:
   - Specific address or symbol location.
   - Calibrated confidence score.
   - Concrete evidence explaining the match.
   - Security classification in `src/opencryptodetect/detection/policy.py`.
5. Add unit and regression tests in `tests/unit/test_signatures.py`.

## Adding Architecture Support

1. Add architecture metadata to `src/opencryptodetect/architecture/metadata.py` and register it in `ARCH_REGISTRY` in `src/opencryptodetect/architecture/architectures.py`.
2. Provide Capstone architecture and mode flags.
3. Define characteristic function prologue byte sequences for stripped binary discovery.
4. Verify cross-compilation with Clang/GCC and test via `tests/unit/test_inspector.py`.

## Pull Request Guidelines

- All PRs must pass `pytest`, `ruff check`, and have no broken tests.
- Do not fabricate benchmark results or claim detection for algorithms without implemented detectors.
- Maintain data-leakage boundaries in all ML dataset additions.
