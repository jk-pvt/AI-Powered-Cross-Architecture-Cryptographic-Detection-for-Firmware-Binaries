"""Safe archive extraction routines with strict traversal and bomb defenses."""

import tarfile
import zipfile
from pathlib import Path

from opencryptodetect.core.exceptions import FirmwareExtractionError, SecurityViolationError
from opencryptodetect.utils.filesystem import sanitize_path

# Max extracted bytes per archive (2 GB)
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024


def safe_extract_zip(zip_path: Path, target_dir: Path) -> list[Path]:
    """Safely extract ZIP archive guarding against directory traversal and zip bombs."""
    extracted_paths: list[Path] = []
    total_bytes = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Check for path traversal in filename
            filename = member.filename
            if filename.startswith(("/", "\\")) or ".." in filename.split("/"):
                raise SecurityViolationError(f"Malicious path in ZIP archive: {filename}")

            dest = sanitize_path(target_dir, filename)

            # Prevent decompression bomb
            total_bytes += member.file_size
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise FirmwareExtractionError(f"Decompression limit exceeded ({total_bytes} bytes)")

            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, dest.open("wb") as dst:
                    while chunk := src.read(65536):
                        dst.write(chunk)
                extracted_paths.append(dest)

    return extracted_paths


def safe_extract_tar(tar_path: Path, target_dir: Path) -> list[Path]:
    """Safely extract TAR archive guarding against traversal and symlink escapes."""
    extracted_paths: list[Path] = []
    total_bytes = 0

    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            filename = member.name
            if filename.startswith(("/", "\\")) or ".." in filename.split("/"):
                raise SecurityViolationError(f"Malicious path in TAR archive: {filename}")

            dest = sanitize_path(target_dir, filename)

            # Check if symlink points outside target directory
            if member.issym() or member.islnk():
                sanitize_path(target_dir, member.linkname)

            total_bytes += member.size
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise FirmwareExtractionError(f"Decompression limit exceeded ({total_bytes} bytes)")

            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                dest.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(member)
                if f:
                    with dest.open("wb") as dst:
                        while chunk := f.read(65536):
                            dst.write(chunk)
                    extracted_paths.append(dest)

    return extracted_paths
