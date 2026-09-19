from pathlib import Path

from opencryptodetect.cbom.cyclonedx import build_cyclonedx_cbom
from opencryptodetect.core.context import AnalysisContext, Finding


def test_cyclonedx_cbom_generation():
    ctx = AnalysisContext(
        file_path=Path("firmware.bin"),
        file_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        file_size_bytes=1048576,
        architecture="arm64",
        findings=[
            Finding(
                algorithm="AES",
                primitive_type="cipher",
                address=0x401000,
                function_name="aes_encrypt",
                confidence=0.96,
                detection_methods=["signature", "ml"],
                evidence=["AES S-box matched in rodata"],
            )
        ],
    )

    cbom = build_cyclonedx_cbom(ctx)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 1
    asset = cbom["components"][0]
    assert asset["name"] == "AES"
    assert asset["cryptoProperties"]["assetType"] == "algorithm"
    assert asset["cryptoProperties"]["algorithmProperties"]["primitive"] == "block-cipher"
