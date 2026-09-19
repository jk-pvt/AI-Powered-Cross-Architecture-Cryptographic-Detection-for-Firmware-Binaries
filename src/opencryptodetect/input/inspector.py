"""File inspection and metadata extraction pipeline."""

import struct
from pathlib import Path

from opencryptodetect.architecture.detector import ArchitectureDetector
from opencryptodetect.core.config import OCDConfig
from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.input.formats import BinaryFormat, detect_file_format
from opencryptodetect.input.validation import validate_input_file
from opencryptodetect.utils.hashing import compute_sha256


class FileInspector:
    """Inspects binary files, detects container formats, architectures, and entry points."""

    def __init__(self, config: OCDConfig | None = None):
        self.config = config or OCDConfig()
        self.arch_detector = ArchitectureDetector(override_arch=self.config.arch_override)

    def inspect(self, file_path: Path) -> AnalysisContext:
        """Inspect input file safely and construct populated AnalysisContext."""
        path = Path(file_path).resolve()
        size, header_bytes = validate_input_file(path, max_size=self.config.max_file_size)
        sha256_hash = compute_sha256(path)

        fmt, desc = detect_file_format(path, header_bytes)
        arch, bitness, endianness = self.arch_detector.detect(path, fmt, header_bytes)

        entry_point = None
        if fmt == BinaryFormat.ELF and len(header_bytes) >= 32:
            entry_point = self._extract_elf_entry(header_bytes, bitness, endianness)

        ctx = AnalysisContext(
            file_path=path,
            file_sha256=sha256_hash,
            file_size_bytes=size,
            file_format=fmt.value,
            architecture=arch.value,
            bitness=bitness,
            endianness=endianness,
            entry_point=entry_point,
        )
        return ctx

    def _extract_elf_entry(self, header_bytes: bytes, bitness: int, endianness: str) -> int | None:
        """Extract entry point address from ELF header."""
        endian_char = "<" if endianness == "little" else ">"
        try:
            if bitness == 64 and len(header_bytes) >= 32:
                # e_entry is at offset 24 (8 bytes)
                return struct.unpack(f"{endian_char}Q", header_bytes[24:32])[0]
            elif bitness == 32 and len(header_bytes) >= 28:
                # e_entry is at offset 24 (4 bytes)
                return struct.unpack(f"{endian_char}I", header_bytes[24:28])[0]
        except Exception:
            pass
        return None
