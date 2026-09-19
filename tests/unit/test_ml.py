from pathlib import Path

import pytest

from opencryptodetect.ml.inference import MLInferenceEngine
from opencryptodetect.ml.model_registry import ModelManifest


def test_model_loading_and_inference():
    model_path = Path("models/model_v1.joblib")
    if not model_path.exists():
        pytest.skip("Model artifact not yet trained")

    engine = MLInferenceEngine(model_path=model_path)
    assert engine.model is not None

    manifest_path = Path("models/manifests/model_v1_manifest.json")
    if manifest_path.exists():
        manifest = ModelManifest.load(manifest_path)
        assert manifest.accuracy > 0.80
        assert manifest.f1_weighted > 0.80
