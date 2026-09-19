"""Cryptographic hashing and entropy utilities."""

import hashlib
import math
from pathlib import Path


def compute_sha256(data_or_path: bytes | str | Path) -> str:
    """Compute SHA-256 hash of byte buffer or file."""
    hasher = hashlib.sha256()
    if isinstance(data_or_path, (str, Path)):
        path = Path(data_or_path)
        with path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    else:
        hasher.update(data_or_path)
    return hasher.hexdigest()


def compute_md5(data_or_path: bytes | str | Path) -> str:
    """Compute MD5 hash of byte buffer or file."""
    hasher = hashlib.md5()
    if isinstance(data_or_path, (str, Path)):
        path = Path(data_or_path)
        with path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    else:
        hasher.update(data_or_path)
    return hasher.hexdigest()


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    frequencies = [0] * 256
    for b in data:
        frequencies[b] += 1

    entropy = 0.0
    for count in frequencies:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy
