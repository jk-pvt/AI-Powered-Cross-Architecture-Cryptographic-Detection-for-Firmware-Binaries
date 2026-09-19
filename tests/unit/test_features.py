import math

from opencryptodetect.binary.functions import FunctionContext, Instruction
from opencryptodetect.features.feature_vector import FEATURE_NAMES, FeatureExtractor


def test_feature_extraction_length_and_no_nan():
    extractor = FeatureExtractor()
    func = FunctionContext(
        address=0x1000,
        name="test_func",
        size_bytes=16,
        architecture="x86_64",
        instructions=[
            Instruction(0x1000, "xor", "eax, eax", b"\x31\xc0", 2, "bitwise"),
            Instruction(0x1002, "ret", "", b"\xc3", 1, "branch"),
        ],
        category_stats={"bitwise": 1, "branch": 1},
        opcode_stats={"xor": 1, "ret": 1},
    )

    vector = extractor.extract_features(func)
    assert len(vector) == len(FEATURE_NAMES)
    for v in vector:
        assert not math.isnan(v)
        assert not math.isinf(v)
