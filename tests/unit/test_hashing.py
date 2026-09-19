import hashlib

from opencryptodetect.utils.hashing import calculate_entropy, compute_md5, compute_sha256


def test_compute_sha256_bytes():
    data = b"OpenCryptoDetect"
    expected = hashlib.sha256(data).hexdigest()
    assert compute_sha256(data) == expected
    assert expected == "692d59836679e02df015b9f6d4be061cbdd796fcbf99d33e995f38f0d82a4304"


def test_compute_md5_bytes():
    data = b"OpenCryptoDetect"
    expected = hashlib.md5(data).hexdigest()
    assert compute_md5(data) == expected
    assert expected == "0bc9fbb9d6d3fb63934ab0b4b0cb4104"


def test_calculate_entropy():
    # Uniform distribution has high entropy (~8.0)
    uniform_bytes = bytes(range(256))
    assert calculate_entropy(uniform_bytes) == 8.0

    # Constant string has 0 entropy
    zero_bytes = b"\x00" * 100
    assert calculate_entropy(zero_bytes) == 0.0
