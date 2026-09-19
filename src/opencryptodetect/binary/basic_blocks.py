"""Basic block modeling and analysis."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BasicBlock:
    """A contiguous sequence of instructions with single entry and single exit."""

    start_address: int
    end_address: int
    instructions: list[Any] = field(default_factory=list)  # List[Instruction]
    successors: set[int] = field(default_factory=set)      # Target block start addresses
    predecessors: set[int] = field(default_factory=set)    # Incoming block start addresses
    is_entry: bool = False
    is_exit: bool = False
    is_loop_header: bool = False

    @property
    def size_bytes(self) -> int:
        return max(0, self.end_address - self.start_address)

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)
