"""Architecture and endianness detection engine."""

import struct
from pathlib import Path

from opencryptodetect.architecture.architectures import ARCH_REGISTRY, normalize_arch_string
from opencryptodetect.architecture.metadata import TargetArch
from opencryptodetect.core.exceptions import ArchitectureDetectionError
from opencryptodetect.input.formats import BinaryFormat


class ArchitectureDetector:
    """Detects target CPU architecture and endianness from binary headers or instruction heuristics."""

    def __init__(self, override_arch: str | None = None):
        self.override_arch = override_arch

    def detect(
        self,
        file_path: Path,
        file_format: BinaryFormat,
        header_bytes: bytes,
    ) -> tuple[TargetArch, int, str]:
        """Returns (arch, bitness, endianness)."""
        # User CLI override takes highest precedence
        if self.override_arch:
            norm = normalize_arch_string(self.override_arch)
            if norm == TargetArch.UNKNOWN:
                raise ArchitectureDetectionError(
                    f"Unsupported architecture override specified: '{self.override_arch}'",
                    details=f"Supported architectures: {', '.join(a.value for a in ARCH_REGISTRY.keys())}",
                )
            meta = ARCH_REGISTRY[norm]
            return norm, meta.bitness, meta.default_endianness

        # Handle ELF format parsing
        if file_format == BinaryFormat.ELF and len(header_bytes) >= 20:
            return self._detect_elf_arch(header_bytes)

        # Handle Mach-O format
        if file_format == BinaryFormat.MACHO and len(header_bytes) >= 8:
            return self._detect_macho_arch(header_bytes)

        # For raw binary, try heuristics or raise error
        heur_arch = self._detect_raw_binary_heuristics(header_bytes)
        if heur_arch != TargetArch.UNKNOWN:
            meta = ARCH_REGISTRY[heur_arch]
            return heur_arch, meta.bitness, meta.default_endianness

        raise ArchitectureDetectionError(
            "Unable to determine architecture automatically for raw binary.",
            details="Use --arch flag to specify architecture (e.g., 'ocd analyze firmware.bin --arch arm').",
        )

    def _detect_elf_arch(self, header_bytes: bytes) -> tuple[TargetArch, int, str]:
        """Extract machine, bitness, and endianness from ELF e_ident and e_machine."""
        # EI_CLASS: header_bytes[4] -> 1: 32-bit, 2: 64-bit
        # EI_DATA:  header_bytes[5] -> 1: Little-endian, 2: Big-endian
        ei_class = header_bytes[4]
        ei_data = header_bytes[5]

        bitness = 64 if ei_class == 2 else 32
        endianness = "little" if ei_data == 1 else "big"
        endian_char = "<" if endianness == "little" else ">"

        # e_machine offset is 18 (2 bytes) in ELF header
        e_machine = struct.unpack(f"{endian_char}H", header_bytes[18:20])[0]

        # e_machine values:
        # 0x03 = EM_386 (x86)
        # 0x3e = EM_X86_64 (x86-64)
        # 0x28 = EM_ARM (ARM 32-bit)
        # 0xb7 = EM_AARCH64 (AArch64 64-bit)
        # 0x08 = EM_MIPS (MIPS)
        # 0xf3 = EM_RISCV (RISC-V)
        machine_map = {
            0x03: (TargetArch.X86, 32),
            0x3E: (TargetArch.X86_64, 64),
            0x28: (TargetArch.ARM, 32),
            0xB7: (TargetArch.AARCH64, 64),
            0x08: (TargetArch.MIPS, 32 if bitness == 32 else 64),
            0xF3: (TargetArch.RISCV, 64 if bitness == 64 else 32),
        }

        if e_machine in machine_map:
            arch, default_bitness = machine_map[e_machine]
            return arch, bitness or default_bitness, endianness

        raise ArchitectureDetectionError(
            f"Unsupported ELF e_machine identifier: 0x{e_machine:02x}",
            details="Supported machines: x86 (0x03), x86-64 (0x3e), ARM (0x28), AArch64 (0xb7), MIPS (0x08), RISC-V (0xf3).",
        )

    def _detect_macho_arch(self, header_bytes: bytes) -> tuple[TargetArch, int, str]:
        """Extract CPU type from Mach-O header."""
        magic = header_bytes[:4]
        endian_char = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
        bitness = 64 if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 32
        endianness = "little" if endian_char == "<" else "big"

        cputype = struct.unpack(f"{endian_char}I", header_bytes[4:8])[0]
        # Mach-O cputype values:
        # 0x01000007 = CPU_TYPE_X86_64
        # 0x0100000c = CPU_TYPE_ARM64
        # 0x07 = CPU_TYPE_X86
        # 0x0c = CPU_TYPE_ARM
        if cputype == 0x01000007:
            return TargetArch.X86_64, 64, endianness
        if cputype == 0x0100000C:
            return TargetArch.AARCH64, 64, endianness
        if cputype == 0x07:
            return TargetArch.X86, 32, endianness
        if cputype == 0x0C:
            return TargetArch.ARM, 32, endianness

        return TargetArch.UNKNOWN, bitness, endianness

    def _detect_raw_binary_heuristics(self, data: bytes) -> TargetArch:
        """Scan raw binary data for distinctive prologue patterns."""
        if not data:
            return TargetArch.UNKNOWN

        # Search for prologue patterns across architectures
        for arch, meta in ARCH_REGISTRY.items():
            for pat in meta.prologue_patterns:
                if pat in data[:2048]:
                    return arch
        return TargetArch.UNKNOWN
