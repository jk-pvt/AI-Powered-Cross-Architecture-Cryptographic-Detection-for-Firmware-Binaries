"""Partition and container header scanning for firmware images."""

from dataclasses import dataclass


@dataclass
class FirmwarePartition:
    """Discovered firmware partition or embedded segment."""

    name: str
    offset: int
    size: int
    partition_type: str  # uimage, squashfs, cpio, tar, zip, raw


# Signatures for embedded filesystems and firmware containers
PARTITION_MAGIC_SIGNATURES = [
    (b"\x27\x05\x19\x56", "uImage header", "uimage"),
    (b"hsqs", "SquashFS little-endian", "squashfs"),
    (b"sqsh", "SquashFS big-endian", "squashfs"),
    (b"070701", "CPIO archive (new ASCII)", "cpio"),
    (b"070702", "CPIO archive (CRC format)", "cpio"),
    (b"PK\x03\x04", "ZIP container", "zip"),
    (b"\x1f\x8b\x08", "GZIP compressed segment", "gzip"),
]


def scan_partitions(data: bytes) -> list[FirmwarePartition]:
    """Scan raw firmware blob for known partition and container headers."""
    partitions: list[FirmwarePartition] = []

    for magic, desc, ptype in PARTITION_MAGIC_SIGNATURES:
        idx = 0
        while True:
            idx = data.find(magic, idx)
            if idx == -1:
                break
            partitions.append(
                FirmwarePartition(
                    name=f"{ptype}_{idx:08x}",
                    offset=idx,
                    size=len(data) - idx,
                    partition_type=ptype,
                )
            )
            idx += len(magic)

    return sorted(partitions, key=lambda p: p.offset)
