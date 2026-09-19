"""Architecture enumeration and register/instruction set metadata."""

from dataclasses import dataclass
from enum import Enum


class TargetArch(str, Enum):
    ARM = "arm"
    AARCH64 = "aarch64"
    X86 = "x86"
    X86_64 = "x86_64"
    MIPS = "mips"
    RISCV = "riscv"
    UNKNOWN = "unknown"


@dataclass
class ArchMetadata:
    """Metadata and conventions for a target architecture."""

    arch: TargetArch
    bitness: int
    default_endianness: str
    register_size: int
    general_registers: list[str]
    prologue_patterns: list[bytes]
    capstone_arch: int
    capstone_mode: int
    description: str
