# Benchmarking & Evaluation Methodology

OpenCryptoDetect includes an automated benchmark suite (`ocd benchmark`) designed to rigorously evaluate and compare detection paradigms across architectures and compilers.

## Benchmarked Approaches

1. **Signature Only**: Evaluates deterministic constants, S-boxes, and table sequence matches without structural heuristics or ML.
2. **Heuristic Only**: Evaluates ARX operation density, bitwise ratios, and loop topology without constant table matching or ML.
3. **ML Only**: Evaluates Random Forest classifier probabilities without deterministic signatures or structural heuristics.
4. **Hybrid Engine**: Evaluates the full evidence fusion pipeline combining signatures, heuristics, and ML probabilities.

## Measured Empirical Results

Evaluated on 169 compiled binary functions across x86-64, AArch64, and ARM architectures spanning optimization levels `-O0` through `-Os`:

| Approach | Precision | Recall | F1-Score | False Positive Rate (FPR) | Avg Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Signature Only** | 0.877 | 0.573 | 0.693 | 0.222 | 0.01 ms |
| **Heuristic Only** | 0.931 | 0.218 | 0.353 | 0.044 | 0.01 ms |
| **ML Only** | 1.000 | 0.782 | 0.878 | 0.000 | 14.79 ms |
| **Hybrid Engine** | 0.882 | 0.726 | 0.796 | 0.267 | 14.51 ms |

### Hybrid Accuracy by Architecture

| Target Architecture | Samples Tested | Empirical Accuracy |
| :--- | :---: | :---: |
| **x86-64** | 57 | 71.9% |
| **AArch64** | 56 | 75.0% |
| **ARM** (32-bit) | 56 | 71.4% |

## Running the Benchmark
```bash
ocd benchmark
```
Results are saved as structured JSON to `benchmarks/results/benchmark_results.json`.
