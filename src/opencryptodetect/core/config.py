"""Runtime configuration for OpenCryptoDetect."""

from dataclasses import dataclass
from pathlib import Path

from opencryptodetect.utils.filesystem import DEFAULT_MAX_FILE_SIZE


@dataclass
class OCDConfig:
    """Configuration options for analysis runs."""

    arch_override: str | None = None
    output_path: Path | None = None
    output_format: str = "terminal"  # terminal, json, cbom, html
    generate_cbom: bool = False
    generate_html: bool = False
    generate_json: bool = False
    verbose: bool = False
    quiet: bool = False
    use_cache: bool = True
    cache_dir: Path | None = None
    model_path: Path | None = None
    signatures_dir: Path | None = None
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    timeout_seconds: float = 60.0
    stage: str | None = None  # e.g., 'inspect', 'binary', 'crypto', 'all'
    enable_ml: bool = True
    enable_heuristics: bool = True
    enable_signatures: bool = True
    enable_library_fingerprint: bool = True
