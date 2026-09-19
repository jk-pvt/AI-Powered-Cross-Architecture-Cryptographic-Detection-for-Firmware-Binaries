"""Heuristic scoring algorithms and weights."""

from opencryptodetect.heuristics.crypto_properties import FunctionHeuristicMetrics


def compute_crypto_likelihood_score(metrics: FunctionHeuristicMetrics) -> float:
    """Calculate normalized cryptographic likelihood score (0.0 to 1.0)."""
    score = 0.0

    # 1. High ARX density is strong indicator of symmetric crypto/hashes
    if metrics.arx_density >= 0.50:
        score += 0.40
    elif metrics.arx_density >= 0.35:
        score += 0.25
    elif metrics.arx_density >= 0.20:
        score += 0.10

    # 2. Presence of bitwise operations (XOR/AND/OR)
    if metrics.bitwise_density >= 0.25:
        score += 0.25
    elif metrics.bitwise_density >= 0.15:
        score += 0.15

    # 3. Presence of shifts and rotations
    if metrics.shift_rotate_density >= 0.15:
        score += 0.15
    elif metrics.shift_rotate_density >= 0.08:
        score += 0.08

    # 4. Loops indicate round iterations
    if metrics.loop_count >= 1:
        score += 0.10

    # 5. Constant density (cryptographic constants or S-box offsets)
    if metrics.constants_count >= 8:
        score += 0.10
    elif metrics.constants_count >= 3:
        score += 0.05

    return min(1.0, score)
