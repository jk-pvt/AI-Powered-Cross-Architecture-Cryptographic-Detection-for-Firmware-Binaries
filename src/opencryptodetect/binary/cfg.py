"""Control Flow Graph (CFG) construction, loop detection, and metrics."""

from dataclasses import dataclass, field

from opencryptodetect.binary.basic_blocks import BasicBlock


@dataclass
class ControlFlowGraph:
    """Directed control flow graph for a single function."""

    entry_address: int
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    edges: list[tuple[int, int]] = field(default_factory=list)  # (src_addr, dst_addr)
    loop_count: int = 0
    back_edges: list[tuple[int, int]] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.blocks)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def cyclomatic_complexity(self) -> int:
        """McCabe cyclomatic complexity: E - N + 2P (P=1 for single function)."""
        n = self.node_count
        e = self.edge_count
        if n == 0:
            return 1
        return max(1, e - n + 2)

    def analyze_loops(self) -> None:
        """Detect natural loops via depth-first search for back-edges."""
        if not self.blocks or self.entry_address not in self.blocks:
            return

        visited: set[int] = set()
        recursion_stack: set[int] = set()
        self.back_edges = []

        def dfs(addr: int) -> None:
            visited.add(addr)
            recursion_stack.add(addr)
            block = self.blocks.get(addr)
            if block:
                for succ in block.successors:
                    if succ not in self.blocks:
                        continue
                    if succ in recursion_stack:
                        # Found a back edge: succ is an ancestor of addr
                        self.back_edges.append((addr, succ))
                        self.blocks[succ].is_loop_header = True
                    elif succ not in visited:
                        dfs(succ)
            recursion_stack.remove(addr)

        dfs(self.entry_address)
        self.loop_count = len(self.back_edges)
