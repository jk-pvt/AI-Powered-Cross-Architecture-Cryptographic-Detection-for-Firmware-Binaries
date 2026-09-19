"""Cross-architecture cryptographic detection benchmarking suite."""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

from opencryptodetect.binary.functions import FunctionContext, Instruction
from opencryptodetect.core.config import OCDConfig
from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.detection.detector import CryptoDetectorEngine
from opencryptodetect.signatures.constants import (
    AES_RCON,
    CHACHA20_CONSTANTS,
    CRC32_POLYNOMIAL_REFLECTED,
    MD5_SINE_TABLE,
    RSA_PUB_EXP_F4,
    SHA256_K,
)

console = Console()
DEFAULT_DATASET = Path(__file__).parent.parent / "dataset" / "metadata" / "features.json"
DEFAULT_OUTPUT = Path(__file__).parent / "results" / "benchmark_results.json"


def build_sample_context(sample: Dict[str, Any]) -> AnalysisContext:
    """Reconstruct an AnalysisContext and FunctionContext from dataset sample metadata and features."""
    feats = sample["features"]
    insn_cnt = max(1, int(feats[0]))

    constants = set()
    if int(feats[24]) > 0:
        constants.update(SHA256_K[: int(feats[24])])
    if int(feats[25]) > 0:
        constants.update(MD5_SINE_TABLE[: int(feats[25])])
    if int(feats[26]) > 0:
        constants.update(AES_RCON[: int(feats[26])])
    if int(feats[27]) > 0:
        constants.update(CHACHA20_CONSTANTS)
    if feats[28] > 0:
        constants.add(RSA_PUB_EXP_F4)
    if feats[29] > 0:
        constants.add(CRC32_POLYNOMIAL_REFLECTED)

    dummy_insns = [
        Instruction(
            address=0x1000 + i * 4,
            mnemonic="nop",
            op_str="",
            bytes=b"\x90",
            size=4,
            category="other",
        )
        for i in range(insn_cnt)
    ]

    func = FunctionContext(
        address=sample.get("function_address", 0x1000),
        name=sample["function_name"],
        size_bytes=int(feats[7]),
        architecture=sample["architecture"],
        instructions=dummy_insns,
        constants=constants,
        category_stats={
            "bitwise": int(feats[10]),
            "shift_rotate": int(feats[11]),
            "arithmetic": int(feats[12]),
            "memory_load": int(feats[13]),
            "memory_store": int(feats[14]),
        },
    )
    func.feature_vector = feats

    ctx = AnalysisContext(
        file_path=Path(f"{sample['algorithm']}_{sample['architecture']}.o"),
        architecture=sample["architecture"],
        functions=[func],
    )
    return ctx


def run_benchmarks(
    dataset_dir: Optional[Path] = None,
    output_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute evaluation comparing Signature-only, Heuristic-only, ML-only, and Hybrid detection."""
    dataset_path = dataset_dir or DEFAULT_DATASET
    output_path = output_file or DEFAULT_OUTPUT

    if not dataset_path.exists():
        console.print("[yellow]Dataset not found. Generating fresh benchmark samples...[/yellow]")
        from dataset.generator.generate_corpus import generate_training_dataset
        dataset_path = generate_training_dataset(output_dir=dataset_path.parent, num_samples=150)

    with dataset_path.open("r", encoding="utf-8") as f:
        samples = json.load(f)

    console.print(f"[bold cyan]Running OpenCryptoDetect Benchmark Suite on {len(samples)} samples...[/bold cyan]\n")

    configs = {
        "Signature Only": OCDConfig(enable_signatures=True, enable_heuristics=False, enable_ml=False),
        "Heuristic Only": OCDConfig(enable_signatures=False, enable_heuristics=True, enable_ml=False),
        "ML Only": OCDConfig(enable_signatures=False, enable_heuristics=False, enable_ml=True),
        "Hybrid Engine": OCDConfig(enable_signatures=True, enable_heuristics=True, enable_ml=True),
    }

    benchmark_results: Dict[str, Any] = {}

    table = Table(title="[bold]Benchmark Comparison: Detection Approaches[/bold]")
    table.add_column("Approach", style="cyan")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1-Score", justify="right")
    table.add_column("FPR", justify="right")
    table.add_column("Avg Time (ms)", justify="right")

    for mode_name, cfg in configs.items():
        detector = CryptoDetectorEngine(cfg)
        tp = 0
        fp = 0
        fn = 0
        tn = 0
        total_time = 0.0

        for s in samples:
            true_label = s["label"]
            is_crypto_true = (true_label != "NonCrypto")

            ctx = build_sample_context(s)
            t0 = time.perf_counter()
            detector.detect(ctx)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            total_time += elapsed_ms

            detected_algs = [f.algorithm for f in ctx.findings]
            is_crypto_pred = len(detected_algs) > 0

            if is_crypto_true and is_crypto_pred:
                tp += 1
            elif not is_crypto_true and is_crypto_pred:
                fp += 1
            elif is_crypto_true and not is_crypto_pred:
                fn += 1
            else:
                tn += 1

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        avg_time = total_time / len(samples) if samples else 0.0

        benchmark_results[mode_name] = {
            "precision": round(prec, 3),
            "recall": round(rec, 3),
            "f1_score": round(f1, 3),
            "fpr": round(fpr, 3),
            "avg_latency_ms": round(avg_time, 3),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
        }

        table.add_row(
            mode_name,
            f"{prec:.3f}",
            f"{rec:.3f}",
            f"{f1:.3f}",
            f"{fpr:.3f}",
            f"{avg_time:.2f}ms",
        )

    console.print(table)
    console.print()

    # Breakdown by Architecture
    arch_table = Table(title="[bold]Hybrid Accuracy by Architecture[/bold]")
    arch_table.add_column("Architecture", style="cyan")
    arch_table.add_column("Samples", justify="right")
    arch_table.add_column("Accuracy", justify="right")

    detector_hybrid = CryptoDetectorEngine(configs["Hybrid Engine"])
    arch_groups: Dict[str, List[Any]] = {}
    for s in samples:
        arch_groups.setdefault(s["architecture"], []).append(s)

    arch_results = {}
    for arch_name, arch_samples in arch_groups.items():
        correct = 0
        for s in arch_samples:
            true_label = s["label"]
            is_crypto_true = (true_label != "NonCrypto")
            c = build_sample_context(s)
            detector_hybrid.detect(c)
            is_pred = len(c.findings) > 0
            if is_pred == is_crypto_true:
                correct += 1
        acc = correct / len(arch_samples) if arch_samples else 0.0
        arch_results[arch_name] = round(acc, 3)
        arch_table.add_row(arch_name.upper(), str(len(arch_samples)), f"{acc:.3f}")

    console.print(arch_table)
    console.print()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.time(),
            "total_samples": len(samples),
            "approaches": benchmark_results,
            "architecture_breakdown": arch_results,
        }, f, indent=2)

    console.print(f"Saved benchmark results to [bold]{output_path}[/bold]")
    return benchmark_results


if __name__ == "__main__":
    run_benchmarks()
