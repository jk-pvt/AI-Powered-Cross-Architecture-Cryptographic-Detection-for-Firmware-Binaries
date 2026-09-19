"""Calculates cryptographic heuristic metrics, operation densities, and ARX properties."""

from dataclasses import dataclass

from opencryptodetect.binary.functions import FunctionContext


@dataclass
class FunctionHeuristicMetrics:
    """Calculated heuristic properties for a single function."""

    instruction_count: int
    bitwise_count: int
    shift_rotate_count: int
    arithmetic_count: int
    memory_load_count: int
    memory_store_count: int
    branch_count: int
    loop_count: int
    cyclomatic_complexity: int
    constants_count: int

    # Normalized densities (0.0 to 1.0)
    bitwise_density: float
    shift_rotate_density: float
    arithmetic_density: float
    memory_density: float
    arx_density: float  # Addition-Rotation-XOR density

    @property
    def is_high_entropy_arx(self) -> bool:
        """Indicates classic ARX cipher/hash characteristics."""
        return self.arx_density > 0.30 and self.instruction_count >= 15


def calculate_heuristic_metrics(func: FunctionContext) -> FunctionHeuristicMetrics:
    """Compute normalized densities and structural metrics from function."""
    total_insns = max(1, func.instruction_count)
    cat_stats = func.category_stats

    bw = cat_stats.get("bitwise", 0)
    sr = cat_stats.get("shift_rotate", 0)
    arith = cat_stats.get("arithmetic", 0)
    m_load = cat_stats.get("memory_load", 0)
    m_store = cat_stats.get("memory_store", 0)
    branch = cat_stats.get("branch", 0)

    loop_cnt = func.cfg.loop_count if func.cfg else 0
    cc = func.cfg.cyclomatic_complexity if func.cfg else 1

    bw_dense = bw / total_insns
    sr_dense = sr / total_insns
    arith_dense = arith / total_insns
    mem_dense = (m_load + m_store) / total_insns
    arx_dense = (bw + sr + arith) / total_insns

    return FunctionHeuristicMetrics(
        instruction_count=total_insns,
        bitwise_count=bw,
        shift_rotate_count=sr,
        arithmetic_count=arith,
        memory_load_count=m_load,
        memory_store_count=m_store,
        branch_count=branch,
        loop_count=loop_cnt,
        cyclomatic_complexity=cc,
        constants_count=len(func.constants),
        bitwise_density=bw_dense,
        shift_rotate_density=sr_dense,
        arithmetic_density=arith_dense,
        memory_density=mem_dense,
        arx_density=arx_dense,
    )
