"""Dataset generation script compiling crypto and non-crypto sources across architectures and optimizations."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console

from opencryptodetect.architecture.architectures import normalize_arch_string
from opencryptodetect.binary.analyzer import ElfCapstoneAnalyzer
from opencryptodetect.features.feature_vector import FeatureExtractor
from opencryptodetect.input.inspector import FileInspector
from opencryptodetect.utils.hashing import compute_sha256
from opencryptodetect.utils.subprocess import safe_run_command

console = Console()

SOURCES = {
    "AES": Path(__file__).parent / "crypto_sources" / "aes.c",
    "SHA256": Path(__file__).parent / "crypto_sources" / "sha256.c",
    "MD5": Path(__file__).parent / "crypto_sources" / "md5.c",
    "ChaCha20": Path(__file__).parent / "crypto_sources" / "chacha20.c",
    "RSA": Path(__file__).parent / "crypto_sources" / "rsa.c",
    "NonCrypto": Path(__file__).parent / "crypto_sources" / "non_crypto.c",
}

ARCH_TARGETS = {
    "x86_64": "x86_64-unknown-linux-gnu",
    "aarch64": "aarch64-linux-gnu",
    "arm": "arm-none-eabi",
}

OPT_LEVELS = ["-O0", "-O1", "-O2", "-O3", "-Os"]


def generate_training_dataset(output_dir: Path, num_samples: int = 100) -> Path:
    """Compile sources, extract features, and produce feature dataset."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "features.json"
    temp_dir = Path(tempfile.mkdtemp(prefix="ocd_dataset_"))

    dataset_entries: List[Dict[str, Any]] = []
    feature_extractor = FeatureExtractor()

    try:
        console.print("[bold cyan]Compiling cryptographic and non-cryptographic dataset corpus...[/bold cyan]")
        sample_idx = 0

        for alg_name, src_path in SOURCES.items():
            if not src_path.exists():
                continue

            for arch_name, target_triple in ARCH_TARGETS.items():
                for opt in OPT_LEVELS:
                    out_obj = temp_dir / f"{alg_name}_{arch_name}_{opt.replace('-', '')}.o"
                    cmd = ["clang", f"-target", target_triple, opt, "-c", str(src_path), "-o", str(out_obj)]

                    code, stdout, stderr = safe_run_command(cmd, timeout_seconds=10.0)
                    if code != 0 or not out_obj.exists():
                        continue

                    bin_hash = compute_sha256(out_obj)

                    try:
                        ctx = FileInspector().inspect(out_obj)
                        arch_enum = normalize_arch_string(ctx.architecture)
                        analyzer = ElfCapstoneAnalyzer(arch=arch_enum, bitness=ctx.bitness, endianness=ctx.endianness)
                        funcs = analyzer.analyze(ctx)

                        for f in funcs:
                            features = feature_extractor.extract_features(f)
                            sample_idx += 1

                            label = alg_name
                            # NonCrypto functions
                            if alg_name == "NonCrypto":
                                label = "NonCrypto"

                            entry = {
                                "sample_id": f"sample_{sample_idx:05d}",
                                "label": label,
                                "algorithm": alg_name,
                                "implementation": "reference_c",
                                "architecture": arch_name,
                                "compiler": "clang",
                                "compiler_version": "17.0.0",
                                "optimization_level": opt,
                                "function_name": f.name,
                                "function_address": f.address,
                                "binary_hash": bin_hash,
                                "features": features,
                            }
                            dataset_entries.append(entry)

                    except Exception as e:
                        console.print(f"[yellow]Skipping {out_obj.name}: {e}[/yellow]")
                        continue

        console.print(f"[bold green]Generated {len(dataset_entries)} labeled function samples![/bold green]")
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(dataset_entries, f, indent=2)

        console.print(f"Dataset saved to: [bold]{out_file}[/bold]")
        return out_file

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
