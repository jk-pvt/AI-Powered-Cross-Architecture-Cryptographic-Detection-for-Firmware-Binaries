"""Analysis context and intermediate state representation."""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TimingMetrics:
    """Detailed stage-by-stage timing measurements."""

    extraction_seconds: float = 0.0
    binary_analysis_seconds: float = 0.0
    feature_extraction_seconds: float = 0.0
    signature_seconds: float = 0.0
    heuristic_seconds: float = 0.0
    ml_inference_seconds: float = 0.0
    fusion_seconds: float = 0.0
    reporting_seconds: float = 0.0
    total_seconds: float = 0.0


@dataclass
class Finding:
    """A detected cryptographic primitive or implementation."""

    algorithm: str
    primitive_type: str  # cipher, hash, asymmetric, mac, checksum, etc.
    address: int
    function_name: str
    confidence: float
    detection_methods: list[str]  # signature, heuristic, ml, cfg
    evidence: list[str]
    security_status: str = "secure"  # secure, deprecated, weak, insecure, non-cryptographic
    security_note: str | None = None
    key_size_bits: int | None = None
    library_candidate: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class LibraryCandidate:
    """A detected cryptographic library fingerprint."""

    library_name: str
    confidence: float
    evidence: list[str]
    likely_version: str | None = None


@dataclass
class AnalysisContext:
    """Complete execution context for analyzing an artifact."""

    file_path: Path
    file_sha256: str = ""
    file_size_bytes: int = 0
    file_format: str = "UNKNOWN"  # ELF, RAW_BIN, INTEL_HEX, etc.
    architecture: str = "UNKNOWN"  # x86_64, arm, aarch64, mips, riscv, etc.
    bitness: int = 64
    endianness: str = "little"
    entry_point: int | None = None
    is_stripped: bool = False

    # Intermediate artifacts
    code_sections: list[dict[str, Any]] = field(default_factory=list)
    data_sections: dict[str, bytes] = field(default_factory=dict)
    relocations: list[dict[str, Any]] = field(default_factory=list)
    functions: list[Any] = field(default_factory=list)  # FunctionContext objects
    extracted_strings: list[str] = field(default_factory=list)

    # Detections and results
    findings: list[Finding] = field(default_factory=list)
    library_candidates: list[LibraryCandidate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    timing: TimingMetrics = field(default_factory=TimingMetrics)

    _start_time: float = field(default_factory=time.time)

    def finish_timing(self) -> None:
        self.timing.total_seconds = time.time() - self._start_time
