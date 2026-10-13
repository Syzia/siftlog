"""Parser for the Cowrie honeypot's JSON log (``cowrie.json``, one object per line).

Cowrie emits many event types. A handful describe what an attacker *did*,
and those become Siftlog events:

=======================================  =================  ===================================
Cowrie ``eventid``                       Siftlog type       Kept in ``extra``
=======================================  =================  ===================================
``cowrie.session.connect``               ``connection``
``cowrie.login.failed``                  ``auth_failure``   ``password`` or key ``fingerprint``
``cowrie.login.success``                 ``auth_success``   ``password`` or key ``fingerprint``
``cowrie.command.input``                 ``command``        ``input``
``cowrie.session.file_upload``           ``file_transfer``  ``filename``, ``shasum``
``cowrie.session.file_download``         ``file_transfer``  ``url``, ``destfile``, ``shasum``
``cowrie.session.file_download.failed``  ``file_transfer``  ``url`` (outcome ``failure``)
=======================================  =================  ===================================

Every event also keeps Cowrie's ``session`` id in ``extra``, which ties one
visitor's connection, logins, commands and files together.

A ``file_transfer`` has a ``direction``: ``upload`` (sent over SFTP or SCP),
``download`` (the honeypot was told to fetch a URL), or ``written``. The last
one is not obvious from the name: Cowrie also logs ``file_download``, with no
``url``, when a shell command writes a file, as in ``echo key >>
.ssh/authorized_keys``. That is a file created on the honeypot, not fetched by
it, and ``destfile`` says where.

Everything else with a well-formed envelope is **ignored with a reason**: session
bookkeeping, client fingerprints, and ``cowrie.command.success`` /
``cowrie.command.failed``, which repeat a ``command.input`` that was already
counted. A line is a **dead letter** only if
it is not something Cowrie would write: not JSON, no event id, no usable
timestamp, or no source address on an event that needs one.

Two things differ from a real server's logs and matter to rules:

* **Almost every login succeeds.** Cowrie lets most guesses in, on purpose.
* **Passwords are logged.** They are attacker guesses, kept because the list of
  what was tried is the point of a honeypot. The same field on a real server's
  log would be a credential leak.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import timezone, tzinfo
from typing import Any, Dict, Mapping, Optional

from siftlog.events import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    COMMAND,
    CONNECTION,
    FILE_TRANSFER,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    DeadLetter,
    Event,
    ParseResult,
    make_event_id,
)
from siftlog.parsers.timestamps import parse_iso

SOURCE = "cowrie"
# Longest attacker-supplied string kept in a structured field. The untouched line stays in `raw`.
MAX_FIELD = 4096

_EVENT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")

# eventid -> (event type, outcome, extra fields to copy, fixed extras)
_MAPPED: Dict[str, Any] = {
    "cowrie.session.connect": (CONNECTION, None, (), {}),
    "cowrie.login.failed": (AUTH_FAILURE, OUTCOME_FAILURE, ("password", "fingerprint"), {}),
    "cowrie.login.success": (AUTH_SUCCESS, OUTCOME_SUCCESS, ("password", "fingerprint"), {}),
    "cowrie.command.input": (COMMAND, None, ("input",), {}),
    "cowrie.session.file_upload": (FILE_TRANSFER, OUTCOME_SUCCESS, ("filename", "shasum", "outfile"), {"direction": "upload"}),
    "cowrie.session.file_download": (FILE_TRANSFER, OUTCOME_SUCCESS, ("url", "destfile", "shasum", "outfile"), {"direction": "download"}),
    "cowrie.session.file_download.failed": (FILE_TRANSFER, OUTCOME_FAILURE, ("url",), {"direction": "download"}),
}  # fmt: skip


def _text(value: Any) -> Optional[str]:
    """A string field, bounded. Anything that is not a string is treated as absent."""
    return value[:MAX_FIELD] if isinstance(value, str) else None


class CowrieParser:
    """Stateless: Cowrie timestamps are absolute, so there is no year to track.

    ``year`` and ``tz`` are accepted and ignored so every parser is built the same way.
    """

    source = SOURCE
    needs_year = False

    def __init__(self, year: Optional[int] = None, tz: tzinfo = timezone.utc) -> None:
        pass

    def state(self) -> Dict[str, Any]:
        return {}

    def restore(self, state: Mapping[str, Any]) -> None:
        pass

    def parse_line(self, line: str, source_id: str, offset: int) -> ParseResult:
        raw = line.rstrip("\r\n")
        if not raw.strip():
            return ParseResult(ignored="blank")

        def dead(reason: str) -> ParseResult:
            return ParseResult(dead_letter=DeadLetter(source_id=source_id, offset=offset, raw=raw, reason=reason))

        try:
            record = json.loads(raw)
        except (ValueError, RecursionError):  # RecursionError: absurdly deep nesting
            return dead("not valid JSON")
        if not isinstance(record, dict):
            return dead("not a JSON object")
        event_id = record.get("eventid")
        if not isinstance(event_id, str) or not _EVENT_ID.fullmatch(event_id):
            return dead("missing or malformed eventid")
        try:
            timestamp = parse_iso(record.get("timestamp"))
        except ValueError:
            return dead("missing or invalid timestamp")

        mapping = _MAPPED.get(event_id)
        if mapping is None:
            return ParseResult(ignored=f"eventid:{event_id}")
        event_type, outcome, copied, fixed = mapping

        src_ip = record.get("src_ip")
        try:
            # The type check matters: ip_address(5) is a valid address, and 5 is not a string.
            if not isinstance(src_ip, str):
                raise ValueError(src_ip)
            ipaddress.ip_address(src_ip)
        except ValueError:
            return dead("missing or invalid src_ip")

        extra: Dict[str, Any] = {"eventid": event_id}
        extra.update(fixed)
        for name in ("session", "protocol") + tuple(copied):
            value = _text(record.get(name))
            if value is not None:
                extra[name] = value
        if event_id == "cowrie.session.file_download" and "url" not in extra:
            # No URL: nothing was fetched. A shell command wrote this file (see the module docstring).
            extra["direction"] = "written"
        dst_port = record.get("dst_port")
        if isinstance(dst_port, int) and not isinstance(dst_port, bool):
            extra["dst_port"] = dst_port

        return ParseResult(
            events=(
                Event(
                    id=make_event_id(source_id, offset),
                    timestamp=timestamp,
                    source=SOURCE,
                    event_type=event_type,
                    src_ip=src_ip,
                    username=_text(record.get("username")),
                    host=_text(record.get("sensor")),
                    outcome=outcome,
                    raw=raw,
                    extra=extra,
                    source_id=source_id,
                    offset=offset,
                ),
            )
        )
