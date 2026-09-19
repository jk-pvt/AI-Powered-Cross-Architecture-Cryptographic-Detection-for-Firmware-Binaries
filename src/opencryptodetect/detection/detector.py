"""Master cryptographic detector orchestrating all detection sub-engines."""


from opencryptodetect.binary.functions import FunctionContext
from opencryptodetect.core.config import OCDConfig
from opencryptodetect.core.context import AnalysisContext, Finding
from opencryptodetect.detection.fusion import EvidenceFusionEngine
from opencryptodetect.features.feature_vector import FeatureExtractor
from opencryptodetect.heuristics.engine import HeuristicEngine
from opencryptodetect.libraries.fingerprint import LibraryFingerprinter
from opencryptodetect.ml.inference import MLInferenceEngine
from opencryptodetect.signatures.engine import SignatureEngine


class CryptoDetectorEngine:
    """Master engine orchestrating signatures, heuristics, ML inference, and evidence fusion."""

    def __init__(self, config: OCDConfig):
        self.config = config
        self.signature_engine = SignatureEngine()
        self.heuristic_engine = HeuristicEngine()
        self.feature_extractor = FeatureExtractor()
        self.ml_engine = MLInferenceEngine(model_path=config.model_path)
        self.library_fingerprinter = LibraryFingerprinter()
        self.fusion_engine = EvidenceFusionEngine()

    def detect(self, ctx: AnalysisContext) -> None:
        """Run all detection phases and attach findings to context."""
        # Step 1: Library Fingerprinting
        if self.config.enable_library_fingerprint:
            ctx.library_candidates = self.library_fingerprinter.fingerprint(ctx)

        # Step 2: Deterministic Signatures
        sig_findings: list[Finding] = []
        if self.config.enable_signatures:
            sig_findings = self.signature_engine.detect_in_context(ctx)

        # Step 3: Heuristics & Feature Extraction & ML
        heuristic_scores: dict[int, float] = {}
        heuristic_evidences: dict[int, list[str]] = {}
        ml_predictions: dict[int, dict[str, float]] = {}
        functions_map: dict[int, FunctionContext] = {}

        for func in ctx.functions:
            functions_map[func.address] = func

            # Heuristics
            if self.config.enable_heuristics:
                h_score, h_ev = self.heuristic_engine.evaluate_function(func)
                heuristic_scores[func.address] = h_score
                heuristic_evidences[func.address] = h_ev

            # ML Inference
            if self.config.enable_ml:
                probs = self.ml_engine.predict_function(func)
                if probs:
                    ml_predictions[func.address] = probs

        # Step 4: Evidence Fusion
        fused = self.fusion_engine.fuse(
            sig_findings=sig_findings,
            heuristic_scores=heuristic_scores,
            heuristic_evidences=heuristic_evidences,
            ml_predictions=ml_predictions,
            functions_map=functions_map,
            ctx=ctx,
        )

        # Step 5: Check for Unknown Crypto (Section 26)
        if self.config.enable_heuristics:
            detected_addrs = {f.address for f in fused}
            for func in ctx.functions:
                unknown_findings = self.heuristic_engine.detect_unknown_crypto(
                    func, already_detected=(func.address in detected_addrs)
                )
                fused.extend(unknown_findings)

        ctx.findings = fused
