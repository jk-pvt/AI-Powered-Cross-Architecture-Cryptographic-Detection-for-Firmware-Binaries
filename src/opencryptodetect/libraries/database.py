"""Fingerprint database for established cryptographic libraries."""

from dataclasses import dataclass


@dataclass
class LibrarySignature:
    name: str
    string_patterns: list[str]
    function_symbol_prefixes: list[str]
    description: str


LIBRARY_SIGNATURES: list[LibrarySignature] = [
    LibrarySignature(
        name="mbedTLS",
        string_patterns=["mbedtls_", "MBEDTLS_", "mbed TLS", "ARM Limited", "Mbed TLS"],
        function_symbol_prefixes=["mbedtls_aes_", "mbedtls_sha256_", "mbedtls_md5_", "mbedtls_rsa_"],
        description="Arm Mbed TLS lightweight embedded SSL/TLS and crypto library",
    ),
    LibrarySignature(
        name="OpenSSL",
        string_patterns=["OpenSSL", "OPENSSL_", "Part of the OpenSSL Project", "libcrypto.so"],
        function_symbol_prefixes=["AES_encrypt", "SHA256_Update", "MD5_Init", "EVP_EncryptInit"],
        description="OpenSSL commercial-grade cryptographic toolkit",
    ),
    LibrarySignature(
        name="wolfSSL",
        string_patterns=["wolfSSL", "WOLFSSL_", "wolfCrypt", "wolfSSL Inc."],
        function_symbol_prefixes=["wc_AesSetKey", "wc_InitSha256", "wc_Md5Update"],
        description="wolfSSL embedded SSL/TLS library",
    ),
    LibrarySignature(
        name="BearSSL",
        string_patterns=["BearSSL", "br_aes_", "br_sha256_"],
        function_symbol_prefixes=["br_aes_big_", "br_sha256_update", "br_rsa_i31_"],
        description="BearSSL compact C cryptographic library",
    ),
    LibrarySignature(
        name="TinyCrypt",
        string_patterns=["tc_aes", "tc_sha256", "tinycrypt"],
        function_symbol_prefixes=["tc_aes128_set_encrypt_key", "tc_sha256_update"],
        description="TinyCrypt constrained device crypto library",
    ),
]
