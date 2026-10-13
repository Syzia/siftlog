"""Batch reader: yields (byte_offset, line) pairs from a file, once."""
from __future__ import annotations

from typing import Iterator, Tuple


def iter_file_lines(path: str) -> Iterator[Tuple[int, str]]:
    """Yield (byte offset of the line start, decoded line without newline).

    The offset feeds deterministic event ids. Logs carry attacker-controlled
    bytes, so decoding never raises: invalid UTF-8 becomes U+FFFD.
    """
    offset = 0
    with open(path, "rb") as fh:
        for chunk in fh:
            yield offset, chunk.decode("utf-8", errors="replace").rstrip("\r\n")
            offset += len(chunk)
