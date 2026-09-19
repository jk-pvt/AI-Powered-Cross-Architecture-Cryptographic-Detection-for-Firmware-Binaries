"""Binary format identification and header parsing."""

import enum
from pathlib import Path


class BinaryFormat(str, enum.Enum):
    ELF = "ELF"
    PE = "PE"
    MACHO = "MACHO"
    INTEL_HEX = "INTEL_HEX"
    RAW_BIN = "RAW_BIN"
    ARCHIVE = "ARCHIVE"  # tar, zip, cpio
    UNKNOWN = "UNKNOWN"


def detect_file_format(file_path: Path, header_bytes: bytes) -> tuple[BinaryFormat, str | None]:
    """Determine binary container format from magic bytes and structure."""
    if len(header_bytes) < 4:
        return BinaryFormat.RAW_BIN, "File smaller than 4 bytes, treated as raw binary"

    # ELF: \x7fELF
    if header_bytes.startswith(b"\x7fELF"):
        return BinaryFormat.ELF, "Standard Executable and Linkable Format"

    # PE: MZ
    if header_bytes.startswith(b"MZ"):
        return BinaryFormat.PE, "Microsoft Portable Executable"

    # Mach-O: \xfe\xed\xfa\xce, \xfe\xed\xfa\xcf, \xce\xfa\xed\xfe, \xcf\xfa\xed\xfe, \xca\xfe\xba\xbe
    if header_bytes.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
        return BinaryFormat.MACHO, "Apple Mach-O Binary"

    # Archives
    if header_bytes.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return BinaryFormat.ARCHIVE, "ZIP Compressed Archive"
    if header_bytes.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
        return BinaryFormat.ARCHIVE, "Compressed Archive"
    if header_bytes.startswith(b"070701") or header_bytes.startswith(b"070702"):
        return BinaryFormat.ARCHIVE, "CPIO Firmware Archive"

    # Intel HEX check: lines start with ':'
    try:
        sample_text = header_bytes[:256].decode("ascii", errors="ignore").strip()
        if sample_text.startswith(":") and all(c in ":0123456789ABCDEFabcdef\r\n" for c in sample_text[:64]):
            return BinaryFormat.INTEL_HEX, "Intel HEX Record Format"
    except Exception:
        pass

    # Default to raw binary/firmware blob
    return BinaryFormat.RAW_BIN, "Raw firmware binary image"
