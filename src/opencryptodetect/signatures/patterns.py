"""Pattern matchers for cryptographic structures and instruction sequences."""


from opencryptodetect.binary.functions import FunctionContext
from opencryptodetect.signatures.constants import AES_INVSBOX, AES_SBOX


def match_sbox_in_bytes(data: bytes) -> str | None:
    """Check if byte buffer contains forward or inverse AES S-box or significant sub-tables."""
    if len(data) < 64:
        return None

    # Exact full match (256 bytes)
    if AES_SBOX in data:
        return "AES Rijndael Forward S-box (256 bytes full match)"
    if AES_INVSBOX in data:
        return "AES Rijndael Inverse S-box (256 bytes full match)"

    # Prefix match (first 64 bytes of S-box)
    if AES_SBOX[:64] in data:
        return "AES Forward S-box sub-table (64 bytes prefix match)"
    if AES_INVSBOX[:64] in data:
        return "AES Inverse S-box sub-table (64 bytes prefix match)"

    return None


def match_chacha20_quarter_round(func: FunctionContext) -> bool:
    """Detect ARX quarter-round instruction pattern in ChaCha20 functions."""
    rotations = {16, 12, 8, 7}
    found_rotations = set()

    for insn in func.instructions:
        if insn.category == "shift_rotate":
            for imm in insn.immediate_values:
                if imm in rotations:
                    found_rotations.add(imm)

    # If function contains shift/rotate operations with 16, 12, 8, and 7
    return rotations.issubset(found_rotations)


def match_hmac_pad_constants(func: FunctionContext) -> bool:
    """Detect HMAC inner/outer padding constant operations (0x36 and 0x5c)."""
    has_ipad = False
    has_opad = False

    for c in func.constants:
        if c in (0x36, 0x3636, 0x36363636):
            has_ipad = True
        if c in (0x5C, 0x5C5C, 0x5C5C5C5C):
            has_opad = True

    return has_ipad and has_opad


def match_table_sequence(data: bytes, table_words: list[int], word_size: int = 4, min_matches: int = 6) -> bool:
    """Search byte stream for sequences of little or big endian constant table words."""
    if len(data) < word_size * min_matches:
        return False

    import struct
    fmt = "<I" if word_size == 4 else "<Q"
    packed_prefix = b"".join(struct.pack(fmt, w) for w in table_words[:min_matches])
    if packed_prefix in data:
        return True

    # Check big endian as well
    fmt_be = ">I" if word_size == 4 else ">Q"
    packed_prefix_be = b"".join(struct.pack(fmt_be, w) for w in table_words[:min_matches])
    if packed_prefix_be in data:
        return True

    return False

