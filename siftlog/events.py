"""The common event schema every parser produces and every later stage consumes."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
# The username was not a valid account. Kept separate from auth_failure because
# sshd usually logs a "Failed password" line for the same attempt, and counting
# both would double the attempt.
INVALID_USER = "invalid_user"
# What a visitor did beyond logging in. Only a honeypot sees these: a real sshd
# does not log the commands a user types or the files they transfer.
CONNECTION = "connection"
COMMAND = "command"
FILE_TRANSFER = "file_transfer"

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"


@dataclass(frozen=True)
class Event:
    id: str
    timestamp: datetime  # always timezone-aware UTC
    source: str  # "sshd", "nginx", "cowrie", ...
    event_type: str
    src_ip: Optional[str]
    username: Optional[str]
    host: Optional[str]
    outcome: Optional[str]
    raw: str  # original line, for audit and debugging
    # >1 when one log line stands for several events ("message repeated N times").
    # Rules must sum this, not count rows, or they undercount during attacks.
    count: int = 1
    geo: Optional[Dict[str, Any]] = None  # filled by enrichment (stage 4)
    # Source-specific fields: ssh auth method, port, pid, http path/status, ...
    extra: Dict[str, Any] = field(default_factory=dict)
    # Provenance: which stream and byte offset the line came from. Together they
    # produce `id`, give a file-order tie-break for events sharing a timestamp
    # (syslog only has one-second resolution), and let an analyst find the line.
    source_id: str = ""
    offset: int = 0

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() != timedelta(0):
            raise ValueError("Event.timestamp must be timezone-aware UTC")
        if self.count < 1:
            raise ValueError("Event.count must be >= 1")


def make_event_id(source_id: str, offset: int) -> str:
    """Deterministic id from where the line came from, not what it says.

    Re-ingesting a file reproduces the same ids, so the store can ignore
    duplicates instead of double-counting. Hashing the raw line alone would be
    wrong: two identical failures in the same second are two events.
    """
    return hashlib.sha256(f"{source_id}\x00{offset}".encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class DeadLetter:
    """A line the parser did not understand. Kept, not dropped."""

    source_id: str
    offset: int
    raw: str
    reason: str


@dataclass(frozen=True)
class ParseResult:
    """Exactly one of: events (possibly empty tuple + ignored), or a dead letter."""

    events: Tuple[Event, ...] = ()
    # Recognised and deliberately not turned into an event (with the reason),
    # as opposed to a dead letter, which means "I don't understand this line".
    ignored: Optional[str] = None
    dead_letter: Optional[DeadLetter] = None
