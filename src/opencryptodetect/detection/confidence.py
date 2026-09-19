"""Calibrated confidence estimation for cryptographic evidence fusion."""



def fuse_confidence_scores(
    sig_confidence: float | None,
    heuristic_score: float,
    ml_probability: float | None,
) -> float:
    """Fuse confidence scores from signature, heuristic, and ML detectors using probabilistic independence."""
    # If a deterministic signature exists:
    if sig_confidence is not None and sig_confidence > 0.0:
        base = sig_confidence
        # Reinforce with ML if consistent
        if ml_probability is not None and ml_probability > 0.5:
            boost = (1.0 - base) * (ml_probability - 0.5) * 0.5
            base += boost
        # Reinforce with heuristic evidence
        if heuristic_score > 0.5:
            base += (1.0 - base) * 0.1
        return min(0.99, round(base, 2))

    # If only ML and heuristics are present:
    if ml_probability is not None and ml_probability >= 0.70:
        combined = (ml_probability * 0.70) + (heuristic_score * 0.30)
        return min(0.95, round(combined, 2))

    # Heuristic alone
    if heuristic_score >= 0.75:
        return min(0.85, round(heuristic_score * 0.85, 2))

    return 0.0
