# OpenCryptoDetect Models & Manifests

This directory contains trained machine learning artifacts and associated provenance manifests used by the function-level classifier.

## Model Artifacts

- **`model_v1.joblib`**: Serialized `RandomForestClassifier` trained on multi-architecture disassembly features (x86-64, ARM, AArch64) across compiler optimization levels `-O0` through `-Os`.
- **`manifests/model_v1_manifest.json`**: Cryptographic checksum, training hyperparameter metadata, class mapping, and feature schema version tracking for `model_v1.joblib`.

## Integrity Verification

Each model must match its recorded SHA-256 digest in the manifest before inference:

```bash
shasum -a 256 models/model_v1.joblib
```

The feature schema version (`v1.0.0`) ensures that inference inputs conform precisely to the 30-feature vector expected by the model.
