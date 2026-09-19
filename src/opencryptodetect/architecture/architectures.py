"""Architecture definitions, register maps, and prologue signatures."""

import capstone

from opencryptodetect.architecture.metadata import ArchMetadata, TargetArch

ARCH_REGISTRY = {
    TargetArch.X86_64: ArchMetadata(
        arch=TargetArch.X86_64,
        bitness=64,
        default_endianness="little",
        register_size=8,
        general_registers=["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
        prologue_patterns=[
            b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
            b"\x48\x83\xec",      # sub rsp, imm8
            b"\x48\x81\xec",      # sub rsp, imm32
            b"\x53\x48\x83\xec",  # push rbx; sub rsp, ...
        ],
        capstone_arch=capstone.CS_ARCH_X86,
        capstone_mode=capstone.CS_MODE_64,
        description="x86-64 / AMD64 64-bit Little Endian",
    ),
    TargetArch.X86: ArchMetadata(
        arch=TargetArch.X86,
        bitness=32,
        default_endianness="little",
        register_size=4,
        general_registers=["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"],
        prologue_patterns=[
            b"\x55\x89\xe5",      # push ebp; mov ebp, esp
            b"\x83\xec",          # sub esp, imm8
            b"\x81\xec",          # sub esp, imm32
        ],
        capstone_arch=capstone.CS_ARCH_X86,
        capstone_mode=capstone.CS_MODE_32,
        description="x86 / IA-32 32-bit Little Endian",
    ),
    TargetArch.AARCH64: ArchMetadata(
        arch=TargetArch.AARCH64,
        bitness=64,
        default_endianness="little",
        register_size=8,
        general_registers=[f"x{i}" for i in range(31)] + ["sp", "pc"],
        prologue_patterns=[
            # stp x29, x30, [sp, #-16]! / stp x29, x30, [sp, -N]!
            b"\xfd\x7b\xbf\xa9",  # stp x29, x30, [sp, #-16]!
            b"\xfd\x7b\xbe\xa9",  # stp x29, x30, [sp, #-32]!
            b"\xfd\x7b\xbd\xa9",  # stp x29, x30, [sp, #-48]!
            b"\xfd\x7b\xbc\xa9",  # stp x29, x30, [sp, #-64]!
            b"\xff\x83\x00\xd1",  # sub sp, sp, #0x20
            b"\xff\x43\x00\xd1",  # sub sp, sp, #0x10
        ],
        capstone_arch=capstone.CS_ARCH_ARM64,
        capstone_mode=capstone.CS_MODE_ARM,
        description="AArch64 / ARM 64-bit Little Endian",
    ),
    TargetArch.ARM: ArchMetadata(
        arch=TargetArch.ARM,
        bitness=32,
        default_endianness="little",
        register_size=4,
        general_registers=[f"r{i}" for i in range(13)] + ["sp", "lr", "pc"],
        prologue_patterns=[
            b"\x00\x48\x2d\xe9",  # push {fp, lr} (ARM mode)
            b"\xf0\x4f\x2d\xe9",  # push {r4-r11, lr} (ARM mode)
            b"\x0f\xb5",          # push {r0-r3, lr} (Thumb mode)
            b"\x80\xb5",          # push {r7, lr} (Thumb mode)
        ],
        capstone_arch=capstone.CS_ARCH_ARM,
        capstone_mode=capstone.CS_MODE_ARM,
        description="ARM 32-bit (ARM / Thumb)",
    ),
    TargetArch.MIPS: ArchMetadata(
        arch=TargetArch.MIPS,
        bitness=32,
        default_endianness="big",
        register_size=4,
        general_registers=["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"],
        prologue_patterns=[
            b"\x27\xbd\xff",      # addiu sp, sp, -N (big endian)
            b"\xff\xbd\x27",      # addiu sp, sp, -N (little endian)
        ],
        capstone_arch=capstone.CS_ARCH_MIPS,
        capstone_mode=capstone.CS_MODE_MIPS32,
        description="MIPS 32-bit",
    ),
    TargetArch.RISCV: ArchMetadata(
        arch=TargetArch.RISCV,
        bitness=64,
        default_endianness="little",
        register_size=8,
        general_registers=[f"x{i}" for i in range(32)],
        prologue_patterns=[
            b"\x13\x01\x01\xff",  # addi sp, sp, -16
            b"\x13\x01\x01\xfe",  # addi sp, sp, -32
        ],
        capstone_arch=capstone.CS_ARCH_RISCV,
        capstone_mode=capstone.CS_MODE_RISCV64,
        description="RISC-V 64-bit",
    ),
}


def get_arch_metadata(arch: TargetArch) -> ArchMetadata:
    """Retrieve metadata for architecture."""
    if arch not in ARCH_REGISTRY:
        raise ValueError(f"Unsupported architecture: {arch}")
    return ARCH_REGISTRY[arch]


def normalize_arch_string(arch_str: str) -> TargetArch:
    """Normalize user or binary arch string to TargetArch enum."""
    cleaned = arch_str.lower().strip()
    if cleaned in ("x86_64", "x86-64", "amd64", "x64", "em64t"):
        return TargetArch.X86_64
    if cleaned in ("x86", "i386", "i686", "ia32"):
        return TargetArch.X86
    if cleaned in ("aarch64", "arm64", "arm64-v8a"):
        return TargetArch.AARCH64
    if cleaned in ("arm", "armv7", "armv7l", "armv7m", "armv6", "thumb"):
        return TargetArch.ARM
    if cleaned in ("mips", "mips32", "mips64", "mipsel", "mipsbe"):
        return TargetArch.MIPS
    if cleaned in ("riscv", "riscv64", "riscv32", "rv64", "rv32"):
        return TargetArch.RISCV
    return TargetArch.UNKNOWN
