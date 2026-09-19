"""Input validation and sanity checking."""

from pathlib import Path

from opencryptodetect.core.exceptions import InputInspectionError
from opencryptodetect.utils.filesystem import DEFAULT_MAX_FILE_SIZE, validate_file_size


def validate_input_file(file_path: Path, max_size: int = DEFAULT_MAX_FILE_SIZE) -> tuple[int, bytes]:
    """Validate that input file is accessible, non-empty, and read initial header bytes."""
    path = Path(file_path).resolve()
    if not path.exists():
        raise InputInspectionError(f"Target file does not exist: {path}")
    if not path.is_file():
        raise InputInspectionError(f"Target path is not a regular file: {path}")

    size = validate_file_size(path, max_size=max_size)
    if size == 0:
        raise InputInspectionError(f"Input file is completely empty (0 bytes): {path}")

    try:
        with path.open("rb") as f:
            header_bytes = f.read(4096)
    except Exception as e:
        raise InputInspectionError(f"Failed to read file header: {e}")

    return size, header_bytes
