"""String extraction from binary sections and data buffers."""



def extract_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """Extract printable ASCII/UTF-8 strings with file/section offsets."""
    results: list[tuple[int, str]] = []
    current_chars: list[int] = []
    start_offset = 0

    for i, byte in enumerate(data):
        # Printable ASCII: 32 (space) to 126 (~), plus tab (\t)
        if 32 <= byte <= 126 or byte == 9:
            if not current_chars:
                start_offset = i
            current_chars.append(byte)
        else:
            if len(current_chars) >= min_len:
                try:
                    s = bytes(current_chars).decode("ascii")
                    results.append((start_offset, s))
                except Exception:
                    pass
            current_chars = []

    # Handle string at the very end
    if len(current_chars) >= min_len:
        try:
            s = bytes(current_chars).decode("ascii")
            results.append((start_offset, s))
        except Exception:
            pass

    return results
