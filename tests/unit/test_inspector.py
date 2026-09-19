from pathlib import Path

import pytest

from opencryptodetect.core.exceptions import InputInspectionError
from opencryptodetect.input.inspector import FileInspector


def test_inspector_x86_64(tmp_path):
    fixture = Path("tests/fixtures/test_x86_64.o")
    if not fixture.exists():
        pytest.skip("Fixture not generated")
    ctx = FileInspector().inspect(fixture)
    assert ctx.architecture == "x86_64"
    assert ctx.bitness == 64
    assert ctx.file_format == "ELF"
    assert len(ctx.file_sha256) == 64


def test_inspector_aarch64(tmp_path):
    fixture = Path("tests/fixtures/test_aarch64.o")
    if not fixture.exists():
        pytest.skip("Fixture not generated")
    ctx = FileInspector().inspect(fixture)
    assert ctx.architecture == "aarch64"
    assert ctx.bitness == 64
    assert ctx.file_format == "ELF"


def test_inspector_arm(tmp_path):
    fixture = Path("tests/fixtures/test_arm.o")
    if not fixture.exists():
        pytest.skip("Fixture not generated")
    ctx = FileInspector().inspect(fixture)
    assert ctx.architecture == "arm"
    assert ctx.bitness == 32
    assert ctx.file_format == "ELF"


def test_empty_file_fails(tmp_path):
    empty_file = tmp_path / "empty.bin"
    empty_file.touch()
    with pytest.raises(InputInspectionError):
        FileInspector().inspect(empty_file)
