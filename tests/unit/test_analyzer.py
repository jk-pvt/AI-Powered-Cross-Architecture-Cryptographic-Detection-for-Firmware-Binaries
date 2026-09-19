from pathlib import Path

import pytest

from opencryptodetect.architecture.architectures import TargetArch
from opencryptodetect.binary.analyzer import ElfCapstoneAnalyzer
from opencryptodetect.input.inspector import FileInspector


def test_analyzer_functions_and_cfg():
    fixture = Path("tests/fixtures/crypto_x86_64.o")
    if not fixture.exists():
        pytest.skip("Fixture not found")

    ctx = FileInspector().inspect(fixture)
    analyzer = ElfCapstoneAnalyzer(TargetArch.X86_64, bitness=64, endianness="little")
    funcs = analyzer.analyze(ctx)

    assert len(funcs) >= 3
    for f in funcs:
        assert f.address is not None
        assert f.instruction_count > 0
        assert f.cfg is not None
        assert f.cfg.cyclomatic_complexity >= 1
        assert len(f.basic_blocks) >= 1
