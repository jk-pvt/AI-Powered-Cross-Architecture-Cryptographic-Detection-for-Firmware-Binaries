"""CBOM generator file writer and validator."""

import json
from pathlib import Path

from opencryptodetect.cbom.cyclonedx import build_cyclonedx_cbom
from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.core.exceptions import CBOMGenerationError


def generate_cbom_report(ctx: AnalysisContext, output_path: Path) -> Path:
    """Generate and write validated CycloneDX 1.6 CBOM report."""
    try:
        cbom_data = build_cyclonedx_cbom(ctx)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(cbom_data, f, indent=2)
        return output_path
    except Exception as e:
        raise CBOMGenerationError(f"Failed to generate CycloneDX CBOM: {e}")
