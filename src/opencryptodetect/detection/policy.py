"""Security policy rules and annotations for deprecated/weak cryptographic algorithms."""

from dataclasses import dataclass


@dataclass
class AlgorithmPolicy:
    """Security classification and guidance for an algorithm."""

    algorithm: str
    status: str  # secure, deprecated, weak, insecure, non-cryptographic
    note: str
    nist_status: str  # Approved, Deprecated, Disallowed, Not Applicable


ALGORITHM_POLICIES: dict[str, AlgorithmPolicy] = {
    "AES": AlgorithmPolicy(
        algorithm="AES",
        status="secure",
        note="FIPS 197 approved symmetric block cipher.",
        nist_status="Approved",
    ),
    "SHA-256": AlgorithmPolicy(
        algorithm="SHA-256",
        status="secure",
        note="FIPS 180-4 approved collision-resistant cryptographic hash.",
        nist_status="Approved",
    ),
    "SHA-512": AlgorithmPolicy(
        algorithm="SHA-512",
        status="secure",
        note="FIPS 180-4 approved cryptographic hash function.",
        nist_status="Approved",
    ),
    "SHA-3": AlgorithmPolicy(
        algorithm="SHA-3",
        status="secure",
        note="FIPS 202 approved permutation-based hash function.",
        nist_status="Approved",
    ),
    "ChaCha20": AlgorithmPolicy(
        algorithm="ChaCha20",
        status="secure",
        note="RFC 8439 approved stream cipher.",
        nist_status="Approved (RFC 8439)",
    ),
    "Poly1305": AlgorithmPolicy(
        algorithm="Poly1305",
        status="secure",
        note="RFC 8439 approved one-time authenticator.",
        nist_status="Approved (RFC 8439)",
    ),
    "RSA": AlgorithmPolicy(
        algorithm="RSA",
        status="secure",
        note="FIPS 186-5 approved asymmetric algorithm (requires >= 2048-bit key).",
        nist_status="Approved (>= 2048-bit)",
    ),
    "ECDSA": AlgorithmPolicy(
        algorithm="ECDSA",
        status="secure",
        note="FIPS 186-5 approved elliptic curve digital signature algorithm.",
        nist_status="Approved",
    ),
    "Ed25519": AlgorithmPolicy(
        algorithm="Ed25519",
        status="secure",
        note="RFC 8032 approved Edwards-curve digital signature algorithm.",
        nist_status="Approved (RFC 8032)",
    ),
    "HMAC": AlgorithmPolicy(
        algorithm="HMAC",
        status="secure",
        note="FIPS 198-1 keyed-hash message authentication code.",
        nist_status="Approved",
    ),
    "MD5": AlgorithmPolicy(
        algorithm="MD5",
        status="weak",
        note="MD5 is cryptographically broken and vulnerable to practical collision attacks.",
        nist_status="Disallowed",
    ),
    "SHA-1": AlgorithmPolicy(
        algorithm="SHA-1",
        status="deprecated",
        note="SHA-1 is deprecated for digital signatures and collision-resistant applications.",
        nist_status="Deprecated",
    ),
    "DES": AlgorithmPolicy(
        algorithm="DES",
        status="insecure",
        note="DES uses a 56-bit key vulnerable to brute force and is considered broken.",
        nist_status="Disallowed",
    ),
    "3DES": AlgorithmPolicy(
        algorithm="3DES",
        status="deprecated",
        note="Triple-DES is retired by NIST due to Sweet32 64-bit block size vulnerabilities.",
        nist_status="Disallowed",
    ),
    "CRC32": AlgorithmPolicy(
        algorithm="CRC32",
        status="non-cryptographic",
        note="CRC32 is an error-detection checksum, not a secure cryptographic primitive.",
        nist_status="Not Applicable",
    ),
}


def get_policy(algorithm_name: str) -> AlgorithmPolicy | None:
    """Retrieve security policy for given algorithm."""
    # Normalize lookup
    for key, policy in ALGORITHM_POLICIES.items():
        if key.lower() in algorithm_name.lower():
            return policy
    return None
