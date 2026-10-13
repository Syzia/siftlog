"""Follow a log file as it grows, the way ``tail -F`` does.

``poll()`` returns the complete lines that have appeared since the last call.
It copes with the three things that happen to a live log:

* **A line still being written.** A final line with no newline is left alone
  until it is complete.
* **Rotation by rename** (``auth.log`` becomes ``auth.log.1`` and a new
  ``auth.log`` appears). The old file is read to its end first, then the new
  one from its start, so nothing written just before the rotation is lost.
* **Truncation in place** (logrotate's ``copytruncate``), or the file being
  replaced by different content. Detected by the file shrinking or its first
  line changing, and treated as a new stream.

Offsets and stream identities are exactly those the batch reader produces, so a
line gets the same event id whichever way it is ingested.
"""
from __future__ import annotations

import hashlib
import os
from typing import IO, Callable, List, Optional, Tuple

from siftlog.ingest.reader import MAX_LINE_BYTES

# Called when a file is identified. Returns (offset, skipping) to resume from, or None to start at 0.
Resume = Callable[[str], Optional[Tuple[int, bool]]]


def _identity(first_line: bytes) -> Optional[str]:
    """Same formula as reader.file_identity, but only once the first line is complete."""
    if first_line.endswith(b"\n") or len(first_line) >= 4096:
        return "file:" + hashlib.sha256(first_line).hexdigest()[:24]
    return None


class TailReader:
    def __init__(self, path: str, resume: Optional[Resume] = None) -> None:
        self.path = path
        self.source_id: Optional[str] = None  # None until the file has a complete first line
        self.offset = 0
        self.skipping = False  # inside an overlong line whose start was already reported
        self._resume = resume
        self._fh: Optional[IO[bytes]] = None
        self._inode: Optional[int] = None

    def poll(self) -> List[Tuple[str, int, str]]:
        """New complete lines since the last call, as (source_id, byte offset, text)."""
        if self._fh is None and not self._open():
            return []
        change = self._change()
        if change == "rewritten":
            # Same file, different content. Our position means nothing in it, so reading
            # first would return half a line of the new content. Start again instead.
            self.close()
            return self._read() if self._open() else []
        # For a rename the old file is still intact behind our handle: read it to the end,
        # including anything written just before the rename, and only then move on.
        lines = self._read()
        if change == "rotated":
            self.close()
            if self._open():
                lines += self._read()
        return lines

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
        self._fh = None
        self._inode = None
        self.source_id = None
        self.offset = 0
        self.skipping = False

    def _open(self) -> bool:
        try:
            self._fh = open(self.path, "rb")
        except FileNotFoundError:
            return False
        self._inode = os.fstat(self._fh.fileno()).st_ino
        return True

    def _identify(self) -> bool:
        assert self._fh is not None
        self._fh.seek(0)
        self.source_id = _identity(self._fh.readline(4096))
        if self.source_id is None:
            return False
        saved = self._resume(self.source_id) if self._resume else None
        if saved is not None:
            self.offset, self.skipping = saved
        return True

    def _read(self) -> List[Tuple[str, int, str]]:
        if self._fh is None or (self.source_id is None and not self._identify()):
            return []
        assert self.source_id is not None
        lines: List[Tuple[str, int, str]] = []
        self._fh.seek(self.offset)
        while True:
            chunk = self._fh.readline(MAX_LINE_BYTES + 1)
            if not chunk:
                break
            if chunk.endswith(b"\n"):
                if self.skipping:
                    self.skipping = False  # the tail of an overlong line: already reported
                else:
                    lines.append((self.source_id, self.offset, _decode(chunk)))
                self.offset += len(chunk)
            elif len(chunk) > MAX_LINE_BYTES:
                # Overlong and still no newline: report a bounded prefix once, skip the rest.
                if not self.skipping:
                    lines.append((self.source_id, self.offset, _decode(chunk[:MAX_LINE_BYTES])))
                    self.skipping = True
                self.offset += len(chunk)
            else:
                break  # an incomplete last line: wait for the rest
        return lines

    def _change(self) -> Optional[str]:
        """What has happened to the path since we opened it.

        ``"rotated"``: it is now a different file (renamed away and recreated).
        ``"rewritten"``: the same file, truncated or overwritten in place.
        ``None``: still the stream being read, or gone and not yet recreated.
        """
        try:
            with open(self.path, "rb") as current:
                stat = os.fstat(current.fileno())
                first = current.readline(4096)
        except FileNotFoundError:
            return None  # rotated away and not recreated yet: keep reading the old file
        if stat.st_ino != self._inode:
            return "rotated"
        if stat.st_size < self.offset:
            return "rewritten"
        if self.source_id is not None and _identity(first) != self.source_id:
            return "rewritten"
        return None


def _decode(chunk: bytes) -> str:
    return chunk.decode("utf-8", errors="replace").rstrip("\r\n")
