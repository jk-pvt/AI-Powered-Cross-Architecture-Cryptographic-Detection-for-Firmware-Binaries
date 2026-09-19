"""Machine learning inference engine for function-level crypto classification."""

from pathlib import Path

import joblib

from opencryptodetect.binary.functions import FunctionContext
from opencryptodetect.features.feature_vector import FeatureExtractor
from opencryptodetect.ml.model_registry import SUPPORTED_CLASSES, ModelManifest
from opencryptodetect.utils.logging import get_logger

logger = get_logger()
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "models" / "model_v1.joblib"


class MLInferenceEngine:
    """Performs local inference using serialized model to predict crypto classes."""

    def __init__(self, model_path: Path | None = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.model = None
        self.manifest: ModelManifest | None = None
        self.feature_extractor = FeatureExtractor()
        self._load_model()

    def _load_model(self) -> None:
        """Attempt to load trained model artifact and manifest."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                manifest_path = self.model_path.parent / "manifests" / f"{self.model_path.stem}_manifest.json"
                if not manifest_path.exists():
                    manifest_path = self.model_path.parent / f"{self.model_path.stem}_manifest.json"
                if manifest_path.exists():
                    self.manifest = ModelManifest.load(manifest_path)
                logger.debug(f"Loaded ML model from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load ML model artifact: {e}")
                self.model = None

    def predict_function(self, func: FunctionContext) -> dict[str, float]:
        """Return class probability distribution for a given function."""
        vector = self.feature_extractor.extract_features(func)

        if self.model is not None:
            try:
                import numpy as np
                x = np.array([vector])
                probs = self.model.predict_proba(x)[0]
                classes = getattr(self.model, "classes_", SUPPORTED_CLASSES)
                return {cls_name: float(prob) for cls_name, prob in zip(classes, probs)}
            except Exception as e:
                logger.debug(f"Inference error: {e}")

        # If model is not loaded yet or encounters unexpected feature mismatch,
        # return an empty probability distribution
        return {}
