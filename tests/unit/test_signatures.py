from opencryptodetect.signatures.constants import AES_INVSBOX, AES_SBOX, SHA256_K
from opencryptodetect.signatures.patterns import match_sbox_in_bytes, match_table_sequence


def test_sbox_matching():
    # Exact full match
    assert match_sbox_in_bytes(AES_SBOX) is not None
    assert match_sbox_in_bytes(AES_INVSBOX) is not None

    # Embedded in larger data
    padded = b"\x00" * 32 + AES_SBOX + b"\xff" * 32
    assert match_sbox_in_bytes(padded) is not None

    # Random data should not match
    assert match_sbox_in_bytes(b"\x00" * 256) is None


def test_sha256_k_table_sequence():
    import struct
    packed = b"".join(struct.pack("<I", w) for w in SHA256_K)
    assert match_table_sequence(packed, SHA256_K, word_size=4, min_matches=6) is True
