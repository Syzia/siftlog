"""Batch reader: yields (byte_offset, line, terminated) from a file, once."""
from __future__ import annotations

import gzip
import hashlib
from typing import IO, Iterator, Tuple

# Logs carry attacker-controlled bytes, so a single "line" can be arbitrarily
# long. Past this many bytes a line is truncated (it will not parse, so it ends
# up in the dead-letter table) and the rest is skipped without being held in memory.
MAX_LINE_BYTES = 64 * 1024


def _open(path: str) -> IO[bytes]:
    # logrotate often gzips rotated logs. Offsets are always uncompressed
    # offsets, so a rotated+compressed copy yields the same event ids.
    return gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")


def iter_file_records(path: str) -> Iterator[Tuple[int, str, bool]]:
    """Yield (byte offset of the line start, decoded line, ended with a newline).

    ``terminated`` is False only for the final line of a file that does not end
    in a newline, which may be a line still being written. Decoding never
    raises: invalid UTF-8 becomes U+FFFD.
    """
    offset = 0
    with _open(path) as fh:
        while True:
            chunk = fh.readline(MAX_LINE_BYTES + 1)
            if not chunk:
                return
            size = len(chunk)
            terminated = chunk.endswith(b"\n")
            if not terminated and size > MAX_LINE_BYTES:
                chunk = chunk[:MAX_LINE_BYTES]
                while True:  # drain the rest of the overlong line, keeping nothing
                    rest = fh.readline(MAX_LINE_BYTES)
                    size += len(rest)
                    if rest.endswith(b"\n"):
                        terminated = True
                        break
                    if not rest:
                        break
            yield offset, chunk.decode("utf-8", errors="replace").rstrip("\r\n"), terminated
            offset += size


def iter_file_lines(path: str) -> Iterator[Tuple[int, str]]:
    """Yield (byte offset, line) pairs. See iter_file_records for details."""
    for offset, line, _ in iter_file_records(path):
        yield offset, line


def file_identity(path: str) -> str:
    """A stable id for a log stream, derived from its first line.

    Not the path: rotation renames auth.log to auth.log.1 (and gzips it), and
    the same events must not be counted again under the new name. A log's first
    line carries a timestamp, so it differs between rotations, but stays the
    same while the file is appended to. Pass an explicit ``source_id`` when two
    streams could share a first line.
    """
    with _open(path) as fh:
        first = fh.readline(4096)
    return "file:" + hashlib.sha256(first).hexdigest()[:24]
