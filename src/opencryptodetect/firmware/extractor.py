"""Safe firmware extractor with provenance tracking and sandboxing."""

from dataclasses import dataclass
from pathlib import Path

from opencryptodetect.firmware.filesystem import safe_extract_tar, safe_extract_zip
from opencryptodetect.input.formats import BinaryFormat, detect_file_format
from opencryptodetect.utils.logging import get_logger

logger = get_logger()


@dataclass
class ExtractedComponent:
    """An executable component extracted from firmware with provenance chain."""

    file_path: Path
    relative_path: str
    provenance: list[str]  # e.g., ["router_firmware.bin", "rootfs.tar.gz", "libcrypto.so"]
    format: BinaryFormat
    size_bytes: int


class FirmwareExtractor:
    """Safely unpacks firmware containers, archives, and embedded executable components."""

    def __init__(self, max_depth: int = 3):
        self.max_depth = max_depth

    def extract_executables(self, firmware_path: Path, output_sandbox: Path) -> list[ExtractedComponent]:
        """Extract and return all executable components without running any code."""
        path = firmware_path.resolve()
        executables: list[ExtractedComponent] = []

        with path.open("rb") as f:
            header = f.read(4096)

        fmt, _ = detect_file_format(path, header)

        # If it's directly an executable ELF/Mach-O/PE, return it as the single component
        if fmt in (BinaryFormat.ELF, BinaryFormat.MACHO, BinaryFormat.PE, BinaryFormat.RAW_BIN):
            executables.append(
                ExtractedComponent(
                    file_path=path,
                    relative_path=path.name,
                    provenance=[path.name],
                    format=fmt,
                    size_bytes=path.stat().st_size,
                )
            )
            # If not an archive, we can return directly
            if fmt != BinaryFormat.ARCHIVE:
                return executables

        # If it is an archive, extract safely into output sandbox
        try:
            if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
                extracted_files = safe_extract_zip(path, output_sandbox)
            elif header.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")) or path.suffix in (".tar", ".tgz", ".gz"):
                extracted_files = safe_extract_tar(path, output_sandbox)
            else:
                extracted_files = [path]

            for ef in extracted_files:
                if ef.is_file():
                    with ef.open("rb") as f:
                        sub_header = f.read(1024)
                    sub_fmt, _ = detect_file_format(ef, sub_header)
                    if sub_fmt in (BinaryFormat.ELF, BinaryFormat.MACHO, BinaryFormat.PE):
                        executables.append(
                            ExtractedComponent(
                                file_path=ef,
                                relative_path=str(ef.relative_to(output_sandbox)),
                                provenance=[path.name, str(ef.relative_to(output_sandbox))],
                                format=sub_fmt,
                                size_bytes=ef.stat().st_size,
                            )
                        )
        except Exception as e:
            logger.warning(f"Failed to unpack container: {e}")

        return executables
