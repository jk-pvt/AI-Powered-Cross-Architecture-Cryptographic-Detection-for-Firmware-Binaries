"""Machine learning model registry, metadata manifests, and serialization."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from opencryptodetect.features.feature_vector import FEATURE_NAMES
from opencryptodetect.utils.hashing import compute_sha256
from opencryptodetect.version import FEATURE_SCHEMA_VERSION, MODEL_VERSION

SUPPORTED_CLASSES: list[str] = [
    "AES",
    "SHA256",
    "MD5",
    "SHA1",
    "ChaCha20",
    "RSA",
    "NonCrypto",
]


@dataclass
class ModelManifest:
    """Metadata manifest describing an exported ML model."""

    model_version: str
    feature_schema_version: str
    feature_names: list[str]
    classes: list[str]
    algorithm: str
    training_samples: int
    accuracy: float
    f1_weighted: float
    created_at: str
    checksum_sha256: str
    description: str = "Cryptographic function classification model"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, output_path: Path) -> None:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, manifest_path: Path) -> "ModelManifest":
        with manifest_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


def export_model_package(
    model_path: Path,
    output_dir: Path,
    manifest: ModelManifest | None = None,
) -> Path:
    """Export model artifact along with manifest JSON and validation checksum."""
    output_dir.mkdir(parents=True, exist_ok=True)
    target_model_file = output_dir / model_path.name
    if model_path != target_model_file:
        import shutil
        shutil.copy2(model_path, target_model_file)

    checksum = compute_sha256(target_model_file)
    manifest_path = output_dir / f"{model_path.stem}_manifest.json"

    if manifest is None:
        manifest = ModelManifest(
            model_version=MODEL_VERSION,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=FEATURE_NAMES,
            classes=SUPPORTED_CLASSES,
            algorithm="RandomForestClassifier",
            training_samples=0,
            accuracy=0.0,
            f1_weighted=0.0,
            created_at=datetime.now(timezone.utc).isoformat(),
            checksum_sha256=checksum,
        )
    else:
        manifest.checksum_sha256 = checksum

    manifest.save(manifest_path)
    return manifest_path
