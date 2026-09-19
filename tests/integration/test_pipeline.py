from pathlib import Path

import pytest

from opencryptodetect.core.config import OCDConfig
from opencryptodetect.core.pipeline import AnalysisPipeline


def test_end_to_end_crypto_x86_64(tmp_path):
    fixture = Path("tests/fixtures/crypto_x86_64.o")
    if not fixture.exists():
        pytest.skip("Fixture not found")

    json_out = tmp_path / "report.json"

    cfg = OCDConfig(
        generate_json=True,
        output_path=json_out,
    )
    pipeline = AnalysisPipeline(cfg)
    ctx = pipeline.run(fixture)

    assert len(ctx.functions) > 0
    assert len(ctx.findings) > 0
    algs = [f.algorithm for f in ctx.findings]
    assert "AES" in algs or "ChaCha20" in algs or "CRC32" in algs

    # Verify report files were created
    assert json_out.exists()


def test_end_to_end_crypto_arm(tmp_path):
    fixture = Path("tests/fixtures/crypto_arm.o")
    if not fixture.exists():
        pytest.skip("Fixture not found")

    cfg = OCDConfig()
    pipeline = AnalysisPipeline(cfg)
    ctx = pipeline.run(fixture)

    assert ctx.architecture == "arm"
    assert len(ctx.findings) > 0
