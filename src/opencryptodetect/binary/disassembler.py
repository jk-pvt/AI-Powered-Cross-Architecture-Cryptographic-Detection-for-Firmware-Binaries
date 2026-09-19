"""Capstone disassembler wrapper with instruction categorization and operand parsing."""

import re

import capstone

from opencryptodetect.architecture.architectures import ARCH_REGISTRY
from opencryptodetect.architecture.metadata import TargetArch
from opencryptodetect.binary.functions import Instruction

# Category keywords by mnemonic family
BITWISE_MNEMONICS = {
    # x86
    "xor", "and", "or", "not", "pxor", "pand", "por", "pandn", "xorps", "xorpd", "andps", "andpd",
    # ARM / AArch64
    "eor", "orr", "orn", "bic", "mvn", "eon", "and",
    # MIPS / RISC-V
    "xori", "andi", "ori", "nor",
}

SHIFT_ROTATE_MNEMONICS = {
    # x86
    "shl", "shr", "sar", "rol", "ror", "rcr", "rcl", "pslld", "psrld", "psrad",
    # ARM / AArch64
    "lsl", "lsr", "asr", "rrx",
    # MIPS / RISC-V
    "sll", "srl", "sra", "slli", "srli", "srai",
}

ARITHMETIC_MNEMONICS = {
    # x86
    "add", "sub", "imul", "mul", "idiv", "div", "inc", "dec", "paddd", "psubd", "pmulld",
    # ARM / AArch64
    "adc", "sbc", "smull", "umull", "sdiv", "udiv", "madd", "msub", "neg",
    # MIPS / RISC-V
    "addu", "subu", "mult", "multu", "divu",
}

BRANCH_MNEMONICS = {
    # x86
    "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "js", "jns",
    # ARM / AArch64
    "b", "beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble", "cbz", "cbnz", "tbz", "tbnz",
    # MIPS / RISC-V
    "bgez", "bgtz", "blez", "bltz", "bnez",
}

CALL_MNEMONICS = {
    # x86
    "call",
    # ARM / AArch64
    "bl", "blr",
    # MIPS / RISC-V
    "jal", "jalr",
}


def categorize_mnemonic(mnemonic: str) -> str:
    """Categorize mnemonic into high-level instruction families."""
    m = mnemonic.lower()
    if m in BITWISE_MNEMONICS:
        return "bitwise"
    if m in SHIFT_ROTATE_MNEMONICS:
        return "shift_rotate"
    if m in ARITHMETIC_MNEMONICS:
        return "arithmetic"
    if m in CALL_MNEMONICS:
        return "call"
    if m in BRANCH_MNEMONICS:
        return "branch"
    if any(m.startswith(p) for p in ("mov", "ldr", "str", "ld", "sd", "lw", "sw")):
        if any(w in m for w in ("str", "sw", "sd", "st")):
            return "memory_store"
        return "memory_load"
    return "other"


class DisassemblerEngine:
    """Disassembler wrapping Capstone with operand analysis."""

    def __init__(self, arch: TargetArch, bitness: int = 64, endianness: str = "little"):
        self.arch = arch
        self.bitness = bitness
        self.endianness = endianness

        meta = ARCH_REGISTRY.get(arch)
        if not meta:
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64
        else:
            cs_arch = meta.capstone_arch
            cs_mode = meta.capstone_mode
            if endianness == "big":
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        self.cs = capstone.Cs(cs_arch, cs_mode)
        self.cs.detail = True

    def disassemble_bytes(
        self,
        code_bytes: bytes,
        base_address: int,
    ) -> list[Instruction]:
        """Disassemble byte buffer into structured Instruction objects."""
        instructions: list[Instruction] = []
        try:
            for insn in self.cs.disasm(code_bytes, base_address):
                cat = categorize_mnemonic(insn.mnemonic)
                immediates: list[int] = []
                ref_addr: int | None = None

                # Extract immediate operands from operands
                try:
                    for op in insn.operands:
                        if op.type == capstone.CS_OP_IMM:
                            val = op.imm
                            # Mask to 32/64 bit signed/unsigned
                            immediates.append(val & 0xFFFFFFFFFFFFFFFF)
                        elif op.type == capstone.CS_OP_MEM:
                            if op.mem.disp != 0:
                                immediates.append(op.mem.disp & 0xFFFFFFFFFFFFFFFF)
                except Exception:
                    # Fallback regex extraction of hex numbers from op_str
                    hex_matches = re.findall(r"0x[0-9a-fA-F]+", insn.op_str)
                    for h in hex_matches:
                        try:
                            immediates.append(int(h, 16))
                        except Exception:
                            pass

                # If this is a direct jump or call, immediate is the target address
                if cat in ("branch", "call") and immediates:
                    ref_addr = immediates[0]

                instruction_obj = Instruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    bytes=bytes(insn.bytes),
                    size=insn.size,
                    category=cat,
                    immediate_values=immediates,
                    referenced_address=ref_addr,
                )
                instructions.append(instruction_obj)
        except Exception:
            pass

        return instructions
