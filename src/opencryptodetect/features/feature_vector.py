"""Function-level feature vector extraction for machine learning and heuristics."""


from opencryptodetect.binary.functions import FunctionContext
from opencryptodetect.signatures.constants import (
    AES_RCON,
    CHACHA20_CONSTANTS,
    CRC32_POLYNOMIAL_REFLECTED,
    MD5_SINE_TABLE,
    RSA_PUB_EXP_F4,
    SHA256_K,
)
from opencryptodetect.version import FEATURE_SCHEMA_VERSION

# Canonical feature names in exact column order (Version 1.0.0)
FEATURE_NAMES: list[str] = [
    "instruction_count",
    "basic_block_count",
    "cfg_edges",
    "loop_count",
    "cyclomatic_complexity",
    "branch_count",
    "call_count",
    "function_size_bytes",
    "constants_count",
    "strings_count",
    "bitwise_count",
    "shift_rotate_count",
    "arithmetic_count",
    "memory_load_count",
    "memory_store_count",
    "bitwise_density",
    "shift_rotate_density",
    "arithmetic_density",
    "memory_density",
    "arx_density",
    "xor_ratio",
    "and_ratio",
    "or_ratio",
    "shift_ratio",
    "sha_k_match_count",
    "md5_sine_match_count",
    "aes_rcon_match_count",
    "chacha_const_match_count",
    "rsa_exp_match",
    "crc32_poly_match",
]


class FeatureExtractor:
    """Extracts numerical feature vector from FunctionContext."""

    def __init__(self) -> None:
        self.schema_version = FEATURE_SCHEMA_VERSION
        self.sha256_k_set = set(SHA256_K)
        self.md5_sine_set = set(MD5_SINE_TABLE)
        self.aes_rcon_set = set(AES_RCON)
        self.chacha_const_set = set(CHACHA20_CONSTANTS)

    def extract_features(self, func: FunctionContext) -> list[float]:
        """Generate numerical feature vector matching FEATURE_NAMES."""
        if func.feature_vector is not None:
            return func.feature_vector

        total_insns = max(1, func.instruction_count)
        cat = func.category_stats
        op = func.opcode_stats

        bw = cat.get("bitwise", 0)
        sr = cat.get("shift_rotate", 0)
        arith = cat.get("arithmetic", 0)
        m_load = cat.get("memory_load", 0)
        m_store = cat.get("memory_store", 0)
        branch = cat.get("branch", 0)
        call_cnt = len(func.calls)

        bb_cnt = func.basic_block_count
        cfg_edges = func.cfg.edge_count if func.cfg else 0
        loop_cnt = func.cfg.loop_count if func.cfg else 0
        cc = func.cfg.cyclomatic_complexity if func.cfg else 1

        # Specific opcode counts (normalized by instruction count)
        xor_cnt = sum(cnt for m, cnt in op.items() if "xor" in m or "eor" in m)
        and_cnt = sum(cnt for m, cnt in op.items() if "and" in m or "bic" in m)
        or_cnt = sum(cnt for m, cnt in op.items() if "or" in m and "xor" not in m and "eor" not in m)
        shift_cnt = sum(cnt for m, cnt in op.items() if any(k in m for k in ("shl", "shr", "sar", "lsl", "lsr", "asr", "sll", "srl", "sra")))

        # Known constant match counts
        c_set = func.constants
        sha_k_matches = len(c_set.intersection(self.sha256_k_set))
        md5_sine_matches = len(c_set.intersection(self.md5_sine_set))
        aes_rcon_matches = len(c_set.intersection(self.aes_rcon_set))
        chacha_matches = len(c_set.intersection(self.chacha_const_set))
        rsa_match = 1.0 if RSA_PUB_EXP_F4 in c_set else 0.0
        crc_match = 1.0 if CRC32_POLYNOMIAL_REFLECTED in c_set else 0.0

        vector = [
            float(total_insns),
            float(bb_cnt),
            float(cfg_edges),
            float(loop_cnt),
            float(cc),
            float(branch),
            float(call_cnt),
            float(func.size_bytes),
            float(len(func.constants)),
            float(len(func.strings)),
            float(bw),
            float(sr),
            float(arith),
            float(m_load),
            float(m_store),
            float(bw / total_insns),
            float(sr / total_insns),
            float(arith / total_insns),
            float((m_load + m_store) / total_insns),
            float((bw + sr + arith) / total_insns),
            float(xor_cnt / total_insns),
            float(and_cnt / total_insns),
            float(or_cnt / total_insns),
            float(shift_cnt / total_insns),
            float(sha_k_matches),
            float(md5_sine_matches),
            float(aes_rcon_matches),
            float(chacha_matches),
            rsa_match,
            crc_match,
        ]

        func.feature_vector = vector
        return vector

    def extract_feature_dict(self, func: FunctionContext) -> dict[str, float]:
        """Extract features as key-value dictionary."""
        vec = self.extract_features(func)
        return dict(zip(FEATURE_NAMES, vec))
