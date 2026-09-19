"""Function and instruction representations."""

from dataclasses import dataclass, field
from typing import Any

from opencryptodetect.binary.basic_blocks import BasicBlock
from opencryptodetect.binary.cfg import ControlFlowGraph


@dataclass
class Instruction:
    """Disassembled instruction representation."""

    address: int
    mnemonic: str
    op_str: str
    bytes: bytes
    size: int
    category: str  # bitwise, arithmetic, shift_rotate, branch, call, memory_load, memory_store, other
    immediate_values: list[int] = field(default_factory=list)
    referenced_address: int | None = None

    def is_bitwise(self) -> bool:
        return self.category in ("bitwise", "shift_rotate")

    def is_branch(self) -> bool:
        return self.category in ("branch", "call")


@dataclass
class FunctionContext:
    """Complete internal representation of an analyzed function."""

    address: int
    name: str
    size_bytes: int
    architecture: str
    instructions: list[Instruction] = field(default_factory=list)
    basic_blocks: list[BasicBlock] = field(default_factory=list)
    cfg: ControlFlowGraph | None = None
    constants: set[int] = field(default_factory=set)
    referenced_data: dict[int, bytes] = field(default_factory=dict)  # addr -> bytes
    strings: list[str] = field(default_factory=list)
    calls: list[int] = field(default_factory=list)
    opcode_stats: dict[str, int] = field(default_factory=dict)
    category_stats: dict[str, int] = field(default_factory=dict)
    feature_vector: list[float] | None = None

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def basic_block_count(self) -> int:
        return len(self.basic_blocks)

    def to_dict(self) -> dict[str, Any]:
        """Serialize function representation to dictionary."""
        return {
            "address": hex(self.address),
            "name": self.name,
            "size_bytes": self.size_bytes,
            "architecture": self.architecture,
            "instruction_count": self.instruction_count,
            "basic_block_count": self.basic_block_count,
            "cyclomatic_complexity": self.cfg.cyclomatic_complexity if self.cfg else 1,
            "loop_count": self.cfg.loop_count if self.cfg else 0,
            "calls": [hex(c) for c in self.calls],
            "constants_count": len(self.constants),
            "strings": self.strings,
            "category_stats": self.category_stats,
        }
