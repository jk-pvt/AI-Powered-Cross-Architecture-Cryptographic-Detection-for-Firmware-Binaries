"""Filesystem security and path management utilities."""

import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from opencryptodetect.core.exceptions import SecurityViolationError

# Maximum default allowed file size (500 MB)
DEFAULT_MAX_FILE_SIZE = 500 * 1024 * 1024


@contextmanager
def secure_temp_dir(prefix: str = "ocd_") -> Generator[Path, None, None]:
    """Provide a secured temporary directory that is guaranteed to be deleted on exit."""
    temp_path = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def sanitize_path(base_dir: str | Path, user_path: str | Path) -> Path:
    """Ensure user_path resolves strictly within base_dir to prevent directory traversal."""
    resolved_base = Path(base_dir).resolve()
    target = (resolved_base / user_path).resolve()

    # Check that target starts with base directory path
    try:
        target.relative_to(resolved_base)
    except ValueError:
        raise SecurityViolationError(
            f"Path traversal detected: {user_path} escapes target directory {base_dir}"
        )
    return target


def validate_file_size(file_path: str | Path, max_size: int = DEFAULT_MAX_FILE_SIZE) -> int:
    """Validate file exists and does not exceed maximum allowable size."""
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    size = path.stat().st_size
    if size > max_size:
        raise SecurityViolationError(
            f"File size ({size} bytes) exceeds safety limit ({max_size} bytes)"
        )
    return size
