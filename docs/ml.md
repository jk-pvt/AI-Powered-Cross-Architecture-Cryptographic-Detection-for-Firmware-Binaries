# Machine Learning Pipeline & Methodology

OpenCryptoDetect uses machine learning specifically for function-level classification to identify cryptographic routines that may use non-standard implementations or stripped tables.

## 1. Feature Schema (v1.0.0)
The model consumes a normalized 30-dimensional feature vector extracted by `FeatureExtractor`:

1. `instruction_count`: Total disassembled instructions.
2. `basic_block_count`: Number of recovered basic blocks.
3. `cfg_edges`: Number of directed control-flow edges.
4. `loop_count`: Number of natural transformation loops detected via DFS back-edges.
5. `cyclomatic_complexity`: McCabe complexity $E - N + 2$.
6. `branch_count`: Conditional and unconditional branch instructions.
7. `call_count`: External and internal call instructions.
8. `function_size_bytes`: Total byte span of the function.
9. `constants_count`: Distinct immediate operands and data constants.
10. `strings_count`: Referenced strings in data sections.
11-15. `category_counts`: Counts of bitwise, shift/rotate, arithmetic, memory load, and memory store instructions.
16-20. `densities`: Proportions of bitwise, shift/rotate, arithmetic, memory access, and overall ARX instructions.
21-24. `ratios`: Ratios of specific instructions (`xor`, `and`, `or`, `shift`).
25-30. `constant_matches`: Counts of matched SHA-256 round keys, MD5 sine table entries, AES Rcon values, ChaCha20 magic words, RSA exponents, and CRC32 polynomials.

## 2. Preventing Data Leakage
To ensure realistic evaluation and prevent overfitting:
- **Implementation Boundaries**: Compilations of the same algorithm are tracked by source implementation ID.
- **Stratified Evaluation**: Evaluation splits ensure unseen optimization levels and compiler variations are tested rather than identical function copies.

## 3. Training & Evaluation CLI Workflow
Generate dataset:
```bash
ocd ml prepare-dataset -n 200
```
Train model:
```bash
ocd ml train --algorithm rf
```
Evaluate performance metrics:
```bash
ocd ml evaluate
```
Export model bundle:
```bash
ocd ml export
```
The exported model package includes `model_v1.joblib` alongside its JSON metadata manifest (`model_v1_manifest.json`) recording training accuracy, weighted F1 score, feature schema version, and cryptographic SHA-256 checksum.
