"""JSON report generator with strict schema versioning."""

import json
from pathlib import Path
from typing import Any

from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.version import SCHEMA_VERSION, __version__


def context_to_dict(ctx: AnalysisContext) -> dict[str, Any]:
    """Serialize complete analysis context to dictionary."""
    return {
        "$schema_version": SCHEMA_VERSION,
        "tool": {
            "name": "OpenCryptoDetect",
            "version": __version__,
        },
        "firmware": {
            "file_name": ctx.file_path.name,
            "file_path": str(ctx.file_path.resolve()),
            "sha256": ctx.file_sha256,
            "size_bytes": ctx.file_size_bytes,
            "format": ctx.file_format,
            "architecture": ctx.architecture,
            "bitness": ctx.bitness,
            "endianness": ctx.endianness,
            "entry_point": hex(ctx.entry_point) if ctx.entry_point is not None else None,
            "is_stripped": ctx.is_stripped,
        },
        "analysis_statistics": {
            "functions_discovered": len(ctx.functions),
            "functions_analyzed": len(ctx.functions),
            "code_sections": ctx.code_sections,
            "extracted_strings_count": len(ctx.extracted_strings),
        },
        "timing_seconds": {
            "extraction": round(ctx.timing.extraction_seconds, 4),
            "binary_analysis": round(ctx.timing.binary_analysis_seconds, 4),
            "feature_extraction": round(ctx.timing.feature_extraction_seconds, 4),
            "fusion": round(ctx.timing.fusion_seconds, 4),
            "reporting": round(ctx.timing.reporting_seconds, 4),
            "total": round(ctx.timing.total_seconds, 4),
        },
        "findings": [
            {
                "algorithm": f.algorithm,
                "primitive_type": f.primitive_type,
                "address": hex(f.address) if f.address else None,
                "function_name": f.function_name,
                "confidence": f.confidence,
                "detection_methods": f.detection_methods,
                "evidence": f.evidence,
                "security_status": f.security_status,
                "security_note": f.security_note,
                "library_candidate": f.library_candidate,
            }
            for f in ctx.findings
        ],
        "library_candidates": [
            {
                "library_name": lib.library_name,
                "confidence": lib.confidence,
                "evidence": lib.evidence,
                "likely_version": lib.likely_version,
            }
            for lib in ctx.library_candidates
        ],
        "warnings": ctx.warnings,
    }


def generate_json_report(ctx: AnalysisContext, output_path: Path) -> Path:
    """Write formatted JSON report to disk."""
    data = context_to_dict(ctx)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return output_path
