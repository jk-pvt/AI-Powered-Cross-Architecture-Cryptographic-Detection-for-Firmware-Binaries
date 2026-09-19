"""Deterministic signature detection engine."""


from opencryptodetect.binary.functions import FunctionContext
from opencryptodetect.core.context import AnalysisContext, Finding
from opencryptodetect.signatures.constants import (
    AES_RCON,
    CHACHA20_CONSTANTS,
    CRC32_POLYNOMIAL_REFLECTED,
    CRC32_POLYNOMIAL_STANDARD,
    CURVE25519_P,
    KECCAK_RC,
    MD5_IV,
    MD5_SINE_TABLE,
    RSA_PUB_EXP_F4,
    SECP256R1_P,
    SHA1_IV,
    SHA1_K,
    SHA256_IV,
    SHA256_K,
    SHA512_K,
)
from opencryptodetect.signatures.patterns import (
    match_chacha20_quarter_round,
    match_hmac_pad_constants,
    match_sbox_in_bytes,
)


class SignatureEngine:
    """Detects cryptographic primitives using deterministic constant and table matching."""

    def __init__(self) -> None:
        self.md5_sine_set = set(MD5_SINE_TABLE)
        self.sha256_k_set = set(SHA256_K)
        self.sha512_k_set = set(SHA512_K)
        self.keccak_rc_set = set(KECCAK_RC)
        self.sha1_k_set = set(SHA1_K)

    def detect_in_context(self, ctx: AnalysisContext) -> list[Finding]:
        """Scan all functions and sections in AnalysisContext for deterministic signatures."""
        findings: list[Finding] = []

        # Check each discovered function
        for func in ctx.functions:
            func_findings = self.detect_function_signatures(func, ctx)
            findings.extend(func_findings)

        # Check global strings and sections for unassociated primitives (e.g. static tables)
        for s in ctx.extracted_strings:
            if "expand 32-byte k" in s and not any(f.algorithm == "ChaCha20" for f in findings):
                findings.append(Finding(
                    algorithm="ChaCha20",
                    primitive_type="cipher",
                    address=ctx.entry_point or 0,
                    function_name="rodata_string",
                    confidence=0.90,
                    detection_methods=["signature"],
                    evidence=["ChaCha20 constant string 'expand 32-byte k' in read-only data"],
                    security_status="secure",
                ))

        # Check data sections for static cryptographic tables
        from opencryptodetect.signatures.patterns import match_table_sequence
        for sec_name, sec_bytes in ctx.data_sections.items():
            # Check AES S-Box
            if not any(f.algorithm == "AES" for f in findings):
                sbox_match = match_sbox_in_bytes(sec_bytes)
                if sbox_match:
                    target_func = ctx.functions[0] if ctx.functions else None
                    addr = target_func.address if target_func else (ctx.entry_point or 0)
                    name = target_func.name if target_func else sec_name
                    findings.append(Finding(
                        algorithm="AES",
                        primitive_type="cipher",
                        address=addr,
                        function_name=name,
                        confidence=0.96,
                        detection_methods=["signature"],
                        evidence=[f"{sbox_match} in section '{sec_name}'"],
                        security_status="secure",
                    ))

            # Check SHA-256 K table
            if not any(f.algorithm == "SHA-256" for f in findings):
                if match_table_sequence(sec_bytes, SHA256_K, word_size=4, min_matches=6):
                    target_func = ctx.functions[0] if ctx.functions else None
                    addr = target_func.address if target_func else (ctx.entry_point or 0)
                    name = target_func.name if target_func else sec_name
                    findings.append(Finding(
                        algorithm="SHA-256",
                        primitive_type="hash",
                        address=addr,
                        function_name=name,
                        confidence=0.97,
                        detection_methods=["signature"],
                        evidence=[f"SHA-256 round constant array K[0..63] detected in section '{sec_name}'"],
                        security_status="secure",
                    ))

            # Check MD5 sine table
            if not any(f.algorithm == "MD5" for f in findings):
                if match_table_sequence(sec_bytes, MD5_SINE_TABLE, word_size=4, min_matches=6):
                    target_func = ctx.functions[0] if ctx.functions else None
                    addr = target_func.address if target_func else (ctx.entry_point or 0)
                    name = target_func.name if target_func else sec_name
                    findings.append(Finding(
                        algorithm="MD5",
                        primitive_type="hash",
                        address=addr,
                        function_name=name,
                        confidence=0.97,
                        detection_methods=["signature"],
                        evidence=[f"MD5 sine table T[1..64] detected in section '{sec_name}'"],
                        security_status="weak",
                        security_note="MD5 is cryptographically broken and vulnerable to collision attacks.",
                    ))

        return findings

    def detect_function_signatures(self, func: FunctionContext, ctx: AnalysisContext) -> list[Finding]:
        """Analyze a single function for signature matches."""
        findings: list[Finding] = []
        c_set = func.constants

        # 1. AES Detection
        # Check referenced data for AES S-box
        sbox_evidence = []
        for ref_addr, data in func.referenced_data.items():
            match_desc = match_sbox_in_bytes(data)
            if match_desc:
                sbox_evidence.append(f"{match_desc} referenced at 0x{ref_addr:x}")

        rcon_matches = [rc for rc in AES_RCON if rc in c_set]
        if sbox_evidence:
            evidence = sbox_evidence
            if len(rcon_matches) >= 3:
                evidence.append(f"AES Rcon key schedule constants matched: {len(rcon_matches)}")
            findings.append(Finding(
                algorithm="AES",
                primitive_type="cipher",
                address=func.address,
                function_name=func.name,
                confidence=0.96,
                detection_methods=["signature"],
                evidence=evidence,
                security_status="secure",
            ))
        elif len(rcon_matches) >= 5:
            findings.append(Finding(
                algorithm="AES",
                primitive_type="cipher",
                address=func.address,
                function_name=func.name,
                confidence=0.85,
                detection_methods=["signature"],
                evidence=[f"Multiple AES Rcon constants ({len(rcon_matches)} matches) detected in function body"],
                security_status="secure",
            ))

        # 2. SHA-256 Detection
        sha256_k_matches = c_set.intersection(self.sha256_k_set)
        sha256_iv_matches = c_set.intersection(set(SHA256_IV))
        if len(sha256_k_matches) >= 3:
            conf = min(0.99, 0.70 + 0.05 * len(sha256_k_matches))
            evidence = [f"Matched {len(sha256_k_matches)} SHA-256 round constants (K[0..63]) in function body"]
            if sha256_iv_matches:
                evidence.append(f"Matched {len(sha256_iv_matches)} SHA-256 initial state constants (H[0..7])")
            findings.append(Finding(
                algorithm="SHA-256",
                primitive_type="hash",
                address=func.address,
                function_name=func.name,
                confidence=conf,
                detection_methods=["signature"],
                evidence=evidence,
                security_status="secure",
            ))
        elif sha256_iv_matches and len(sha256_iv_matches) >= 4:
            findings.append(Finding(
                algorithm="SHA-256",
                primitive_type="hash",
                address=func.address,
                function_name=func.name,
                confidence=0.88,
                detection_methods=["signature"],
                evidence=[f"Matched {len(sha256_iv_matches)} SHA-256 initial state constants (H0..H7)"],
                security_status="secure",
            ))

        # 3. MD5 Detection
        md5_sine_matches = c_set.intersection(self.md5_sine_set)
        md5_iv_matches = c_set.intersection(set(MD5_IV))
        if len(md5_sine_matches) >= 3:
            conf = min(0.99, 0.70 + 0.05 * len(md5_sine_matches))
            evidence = [f"Matched {len(md5_sine_matches)} MD5 per-round sine table constants (T[1..64])"]
            if md5_iv_matches:
                evidence.append(f"Matched {len(md5_iv_matches)} MD5 initialization vectors")
            findings.append(Finding(
                algorithm="MD5",
                primitive_type="hash",
                address=func.address,
                function_name=func.name,
                confidence=conf,
                detection_methods=["signature"],
                evidence=evidence,
                security_status="weak",
                security_note="MD5 is cryptographically broken and vulnerable to collision attacks.",
            ))

        # 4. SHA-1 Detection
        sha1_k_matches = c_set.intersection(self.sha1_k_set)
        sha1_iv_matches = c_set.intersection(set(SHA1_IV))
        if len(sha1_k_matches) >= 2:
            conf = 0.90 if len(sha1_k_matches) >= 3 else 0.82
            evidence = [f"Matched {len(sha1_k_matches)} SHA-1 round constants (K0..K3)"]
            if sha1_iv_matches:
                evidence.append(f"Matched {len(sha1_iv_matches)} SHA-1 state constants (H0..H4)")
            findings.append(Finding(
                algorithm="SHA-1",
                primitive_type="hash",
                address=func.address,
                function_name=func.name,
                confidence=conf,
                detection_methods=["signature"],
                evidence=evidence,
                security_status="deprecated",
                security_note="SHA-1 is deprecated for collision-resistant security applications.",
            ))

        # 5. SHA-512 Detection
        sha512_k_matches = c_set.intersection(self.sha512_k_set)
        if len(sha512_k_matches) >= 3:
            findings.append(Finding(
                algorithm="SHA-512",
                primitive_type="hash",
                address=func.address,
                function_name=func.name,
                confidence=0.95,
                detection_methods=["signature"],
                evidence=[f"Matched {len(sha512_k_matches)} SHA-512 64-bit round constants"],
                security_status="secure",
            ))

        # 6. SHA-3 / Keccak Detection
        keccak_matches = c_set.intersection(self.keccak_rc_set)
        if len(keccak_matches) >= 3:
            findings.append(Finding(
                algorithm="SHA-3",
                primitive_type="hash",
                address=func.address,
                function_name=func.name,
                confidence=0.95,
                detection_methods=["signature"],
                evidence=[f"Matched {len(keccak_matches)} Keccak round constants RC[0..23]"],
                security_status="secure",
            ))

        # 7. ChaCha20 Detection
        chacha_imm_match = any(c in c_set for c in CHACHA20_CONSTANTS)
        chacha_qr = match_chacha20_quarter_round(func)
        if chacha_imm_match or chacha_qr:
            ev = []
            if chacha_imm_match:
                ev.append("ChaCha20 expansion constant word matched in operands")
            if chacha_qr:
                ev.append("Quarter-round ARX rotation set (16, 12, 8, 7) present")
            findings.append(Finding(
                algorithm="ChaCha20",
                primitive_type="cipher",
                address=func.address,
                function_name=func.name,
                confidence=0.92 if (chacha_imm_match and chacha_qr) else 0.80,
                detection_methods=["signature"],
                evidence=ev,
                security_status="secure",
            ))

        # 8. HMAC Detection
        if match_hmac_pad_constants(func):
            findings.append(Finding(
                algorithm="HMAC",
                primitive_type="mac",
                address=func.address,
                function_name=func.name,
                confidence=0.88,
                detection_methods=["signature"],
                evidence=["HMAC ipad (0x36) and opad (0x5c) padding constants present in function arithmetic"],
                security_status="secure",
            ))

        # 9. RSA Detection
        if RSA_PUB_EXP_F4 in c_set:
            findings.append(Finding(
                algorithm="RSA",
                primitive_type="asymmetric",
                address=func.address,
                function_name=func.name,
                confidence=0.85,
                detection_methods=["signature"],
                evidence=["Standard RSA public exponent 65537 (0x10001) referenced in function"],
                security_status="secure",
            ))

        # 10. ECC / ECDSA Curve Parameters
        if SECP256R1_P in c_set:
            findings.append(Finding(
                algorithm="ECDSA",
                primitive_type="asymmetric",
                address=func.address,
                function_name=func.name,
                confidence=0.95,
                detection_methods=["signature"],
                evidence=["NIST P-256 (secp256r1) prime field constant present"],
                security_status="secure",
            ))
        elif CURVE25519_P in c_set:
            findings.append(Finding(
                algorithm="Ed25519",
                primitive_type="asymmetric",
                address=func.address,
                function_name=func.name,
                confidence=0.95,
                detection_methods=["signature"],
                evidence=["Curve25519 prime 2^255 - 19 constant present"],
                security_status="secure",
            ))

        # 11. CRC32 Detection (Explicitly non-cryptographic checksum)
        if CRC32_POLYNOMIAL_REFLECTED in c_set or CRC32_POLYNOMIAL_STANDARD in c_set:
            poly_name = "0xEDB88320 (IEEE 802.3 reflected)" if CRC32_POLYNOMIAL_REFLECTED in c_set else "0x04C11DB7"
            findings.append(Finding(
                algorithm="CRC32",
                primitive_type="checksum",
                address=func.address,
                function_name=func.name,
                confidence=0.95,
                detection_methods=["signature"],
                evidence=[f"CRC32 generator polynomial {poly_name} matched"],
                security_status="non-cryptographic",
                security_note="CRC32 is an error-detecting checksum, not a secure cryptographic hash.",
            ))

        return findings
