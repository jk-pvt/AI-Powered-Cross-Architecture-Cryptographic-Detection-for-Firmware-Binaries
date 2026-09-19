import zipfile

import pytest

from opencryptodetect.core.exceptions import (
    ArchitectureDetectionError,
    SecurityViolationError,
)
from opencryptodetect.firmware.filesystem import safe_extract_zip
from opencryptodetect.input.inspector import FileInspector
from opencryptodetect.utils.filesystem import sanitize_path, validate_file_size


def test_directory_traversal_prevention(tmp_path):
    base = tmp_path / "sandbox"
    base.mkdir()

    # Attempting to escape sandbox with ../
    with pytest.raises(SecurityViolationError):
        sanitize_path(base, "../../../etc/passwd")


def test_zip_path_traversal_detection(tmp_path):
    zip_path = tmp_path / "malicious.zip"
    target_dir = tmp_path / "extracted"
    target_dir.mkdir()

    # Craft zip file with malicious filename
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../escape.txt", "malicious payload")

    with pytest.raises(SecurityViolationError):
        safe_extract_zip(zip_path, target_dir)


def test_truncated_elf_handling(tmp_path):
    truncated_elf = tmp_path / "truncated.elf"
    # ELF magic only without body
    truncated_elf.write_bytes(b"\x7fELF\x02\x01\x01\x00")

    with pytest.raises(ArchitectureDetectionError):
        FileInspector().inspect(truncated_elf)


def test_file_size_limit_enforcement(tmp_path):
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"\x00" * 1024)

    # Set limit below file size
    with pytest.raises(SecurityViolationError):
        validate_file_size(large_file, max_size=512)
