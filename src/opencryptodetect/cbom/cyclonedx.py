"""CycloneDX 1.6 CBOM (Cryptographic Bill of Materials) builder."""

import uuid
from datetime import datetime, timezone
from typing import Any

from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.version import CBOM_SPEC_VERSION, __version__

PRIMITIVE_MAP = {
    "cipher": "block-cipher",
    "hash": "digest",
    "asymmetric": "signature",
    "mac": "mac",
    "checksum": "non-cryptographic",
    "unknown_crypto": "unknown",
}


def build_cyclonedx_cbom(ctx: AnalysisContext) -> dict[str, Any]:
    """Generate CycloneDX 1.6 compliant CBOM JSON representation."""
    bom_uuid = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    components: list[dict[str, Any]] = []

    for idx, finding in enumerate(ctx.findings):
        asset_id = f"crypto-asset-{idx+1}"
        primitive_cyclonedx = PRIMITIVE_MAP.get(finding.primitive_type, "other")

        component_entry: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": asset_id,
            "name": finding.algorithm,
            "version": finding.library_candidate or "embedded-implementation",
            "description": f"Detected {finding.algorithm} at address 0x{finding.address:x} ({finding.function_name})",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": primitive_cyclonedx,
                    "executionEnvironment": "software-plain-binary",
                    "implementationPlatform": ctx.architecture,
                    "cryptoFunctions": [finding.algorithm],
                },
                "detectionContext": {
                    "detectionMethods": finding.detection_methods,
                    "confidence": finding.confidence,
                    "location": {
                        "address": hex(finding.address),
                        "symbol": finding.function_name,
                        "file": ctx.file_path.name,
                    },
                    "evidence": finding.evidence,
                },
                "securityStatus": {
                    "classification": finding.security_status,
                    "advisoryNote": finding.security_note or "N/A",
                },
            },
        }
        components.append(component_entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CBOM_SPEC_VERSION,
        "serialNumber": bom_uuid,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "OpenCryptoDetect",
                        "version": __version__,
                        "description": "Open-source cross-architecture cryptographic primitive detection CLI",
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "name": ctx.file_path.name,
                "version": "1.0.0",
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": ctx.file_sha256,
                    }
                ],
                "properties": [
                    {"name": "architecture", "value": ctx.architecture},
                    {"name": "bitness", "value": str(ctx.bitness)},
                    {"name": "endianness", "value": ctx.endianness},
                    {"name": "format", "value": ctx.file_format},
                ],
            },
        },
        "components": components,
    }
