"""Content-addressed analysis caching."""

import json
from pathlib import Path
from typing import Any

from opencryptodetect.utils.hashing import compute_sha256
from opencryptodetect.version import (
    FEATURE_SCHEMA_VERSION,
    MODEL_VERSION,
    SCHEMA_VERSION,
    SIGNATURE_DB_VERSION,
    __version__,
)

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "opencryptodetect"


class AnalysisCache:
    """Content-addressed cache keyed by input SHA-256 and version fingerprint."""

    def __init__(self, cache_dir: Path | None = None, enabled: bool = True):
        self.enabled = enabled
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _generate_cache_key(self, file_sha256: str) -> str:
        """Create version-pinned cache key."""
        version_payload = (
            f"{file_sha256}:{__version__}:{SCHEMA_VERSION}:"
            f"{FEATURE_SCHEMA_VERSION}:{MODEL_VERSION}:{SIGNATURE_DB_VERSION}"
        )
        return compute_sha256(version_payload.encode("utf-8"))

    def get(self, file_sha256: str) -> dict[str, Any] | None:
        """Retrieve cached analysis if valid and available."""
        if not self.enabled:
            return None
        key = self._generate_cache_key(file_sha256)
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with cache_file.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def put(self, file_sha256: str, analysis_data: dict[str, Any]) -> None:
        """Store analysis result into content-addressed cache."""
        if not self.enabled:
            return
        key = self._generate_cache_key(file_sha256)
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with cache_file.open("w", encoding="utf-8") as f:
                json.dump(analysis_data, f, indent=2)
        except Exception:
            pass
