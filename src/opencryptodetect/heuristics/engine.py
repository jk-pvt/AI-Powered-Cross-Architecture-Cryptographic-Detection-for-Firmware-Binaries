"""Heuristic analysis engine for cryptographic patterns and unknown crypto detection."""


from opencryptodetect.binary.functions import FunctionContext
from opencryptodetect.core.context import Finding
from opencryptodetect.heuristics.crypto_properties import calculate_heuristic_metrics
from opencryptodetect.heuristics.scoring import compute_crypto_likelihood_score


class HeuristicEngine:
    """Evaluates functions using structural heuristics, ARX density, and loop topologies."""

    def evaluate_function(self, func: FunctionContext) -> tuple[float, list[str]]:
        """Calculate crypto score and gather explanatory evidence."""
        metrics = calculate_heuristic_metrics(func)
        score = compute_crypto_likelihood_score(metrics)

        evidence: list[str] = []
        if metrics.arx_density >= 0.35:
            evidence.append(f"High ARX operation density: {metrics.arx_density:.1%}")
        if metrics.bitwise_density >= 0.15:
            evidence.append(f"Elevated bitwise operation density: {metrics.bitwise_density:.1%}")
        if metrics.shift_rotate_density >= 0.08:
            evidence.append(f"Significant shift/rotate instructions: {metrics.shift_rotate_density:.1%}")
        if metrics.loop_count > 0:
            evidence.append(f"Function contains {metrics.loop_count} transformation loops")
        if metrics.cyclomatic_complexity >= 5:
            evidence.append(f"Cyclomatic complexity of {metrics.cyclomatic_complexity}")

        return score, evidence

    def detect_unknown_crypto(self, func: FunctionContext, already_detected: bool) -> list[Finding]:
        """Detect potential unknown or custom cryptographic implementations (Section 26)."""
        if already_detected:
            return []

        metrics = calculate_heuristic_metrics(func)
        score = compute_crypto_likelihood_score(metrics)

        # Triggers only when high crypto likelihood exists without matched signatures
        if score >= 0.70 and metrics.instruction_count >= 20 and metrics.arx_density >= 0.40:
            evidence = [
                f"High bitwise and arithmetic density ({metrics.arx_density:.1%}) characteristic of cryptographic routines",
                f"Iterative transformation structure with {metrics.loop_count} loops",
                "No exact match against known standard signature database",
            ]
            return [
                Finding(
                    algorithm="Potential unknown cryptographic implementation",
                    primitive_type="unknown_crypto",
                    address=func.address,
                    function_name=func.name,
                    confidence=score * 0.85,  # Scale confidence appropriately
                    detection_methods=["heuristic"],
                    evidence=evidence,
                    security_status="experimental",
                    security_note="Experimental finding: function exhibits high crypto density without matching known primitives.",
                )
            ]
        return []
