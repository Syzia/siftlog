"""Parser for OpenSSH server (sshd) auth log lines.

Three outcomes per line, deliberately distinct:

* **event**: an authentication fact the engine cares about.
* **ignored**: recognised and understood, but not an event (session housekeeping,
  PAM chatter that duplicates a line we already count). Each has a reason.
* **dead letter**: not understood. These are kept, so parser gaps stay visible.

Handles both classic syslog (``Oct 13 11:16:02 host sshd[1]: ...``, no year, no
timezone) and ISO 8601 / rsyslog high-precision timestamps.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Dict, Mapping, Optional

from siftlog.events import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    INVALID_USER,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    DeadLetter,
    Event,
    ParseResult,
    make_event_id,
)

SOURCE = "sshd"

# OpenSSH 9.8+ splits the daemon into sshd-session / sshd-auth, and the syslog
# program name follows.
SSHD_PROGRAMS = frozenset({"sshd", "sshd-session", "sshd-auth"})

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

_PROG = r"(?P<prog>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+" + _PROG
)
_ISO = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})\s+(?P<host>\S+)\s+" + _PROG
)

# rsyslog collapses identical lines: "message repeated 5 times: [ <original>]".
_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times?: \[ ?(?P<inner>.*?) ?\]$")

# Usernames are attacker-controlled and may contain spaces or text that looks
# like the rest of the line ("admin from 192.0.2.9 port 1"). Every pattern is
# anchored at the END of the line and the user group is greedy, so the address
# is always taken from the last structural "from <ip> port <n>", which sshd wrote.
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.+) "
    r"from (?P<ip>\S+) port (?P<port>\d+) ssh2(?::.*)?$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.+) "
    r"from (?P<ip>\S+) port (?P<port>\d+) ssh2(?::.*)?$"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")

# Known, understood, not events. Anything from sshd that matches neither an event
# pattern nor one of these is a dead letter.
_IGNORED = [
    # pam_unix logs the same failure sshd already reports as "Failed password";
    # counting both would double every attempt.
    (re.compile(r"^pam_\w+\(sshd:\w+\): .*$"), "pam-module"),
    (re.compile(r"^PAM \d+ more authentication failures?; .*$"), "pam-summary"),
    (re.compile(r"^PAM service\(sshd\) ignoring max retries; .*$"), "pam-notice"),
    (
        re.compile(r"^Connection closed by (?:authenticating|invalid) user .+ \S+ port \d+(?: \[preauth\])?$"),
        "connection-closed",
    ),
    (re.compile(r"^Connection closed by \S+ port \d+(?: \[preauth\])?$"), "connection-closed"),
    (
        re.compile(r"^Connection reset by (?:(?:authenticating|invalid) user .+ )?\S+ port \d+(?: \[preauth\])?$"),
        "connection-reset",
    ),
    (
        re.compile(r"^Disconnected from (?:(?:authenticating|invalid) )?user .+ \S+ port \d+(?: \[preauth\])?$"),
        "disconnected",
    ),
    (re.compile(r"^Disconnected from \S+ port \d+(?: \[preauth\])?$"), "disconnected"),
    (re.compile(r"^Disconnecting(?: (?:authenticating|invalid) user .+ \S+ port \d+)?: .*$"), "disconnecting"),
    (re.compile(r"^Received disconnect from \S+ port \d+:\d+: .*$"), "received-disconnect"),
    (
        re.compile(
            r"^(?:error: )?maximum authentication attempts exceeded for .+ from \S+ port \d+ ssh2(?: \[preauth\])?$"
        ),
        "max-auth-tries",
    ),
    (re.compile(r"^Did not receive identification string from \S+(?: port \d+)?$"), "no-banner"),
    (re.compile(r"^Unable to negotiate with \S+ port \d+: .*$"), "negotiation-failed"),
    (re.compile(r"^Bad protocol version identification .* from \S+ port \d+$"), "bad-banner"),
    (re.compile(r"^banner exchange: .*$"), "banner-exchange"),
    (re.compile(r"^error: kex_exchange_identification: .*$"), "kex-identification"),
    (re.compile(r"^Server listening on .*$"), "lifecycle"),
    (re.compile(r"^Received signal \d+; terminating\.$"), "lifecycle"),
    (re.compile(r"^(?:Starting session|Session \d+ logged out)\b.*$"), "session"),
    (re.compile(r"^Postponed \S+ for .+ from \S+ port \d+ ssh2(?: \[preauth\])?$"), "postponed"),
]


class SshdParser:
    """Stateful because classic syslog timestamps carry no year.

    ``year`` is the year of the first line. The parser bumps it by one when the
    month number jumps backwards (December to January), so feed lines in file
    order. ``tz`` is the timezone the host logged in; timestamps are converted
    to UTC. Ambiguous local times at a DST change are not disambiguated.
    """

    source = SOURCE

    def __init__(self, year: int, tz: tzinfo = timezone.utc) -> None:
        self._year = year
        self._tz = tz
        self._last_month: Optional[int] = None

    def state(self) -> Dict[str, Optional[int]]:
        """What must be saved to resume parsing mid-stream: the year being assumed."""
        return {"year": self._year, "last_month": self._last_month}

    def restore(self, state: Mapping[str, Optional[int]]) -> None:
        self._year = int(state["year"])  # type: ignore[arg-type]
        self._last_month = state.get("last_month")

    def parse_line(self, line: str, source_id: str, offset: int) -> ParseResult:
        raw = line.rstrip("\r\n")
        if not raw.strip():
            return ParseResult(ignored="blank")

        syslog = _SYSLOG.match(raw)
        match = syslog or _ISO.match(raw)
        if match is None:
            return _dead(raw, source_id, offset, "unrecognised log envelope")
        try:
            timestamp = self._timestamp(match) if syslog else _iso_timestamp(match)
        except ValueError as exc:
            return _dead(raw, source_id, offset, f"invalid timestamp: {exc}")

        program = match.group("prog")
        if program not in SSHD_PROGRAMS:
            return ParseResult(ignored=f"program:{program}")

        message = match.group("msg")
        count = 1
        repeated = _REPEATED.match(message)
        if repeated:
            count = int(repeated.group("n"))
            message = repeated.group("inner")

        for pattern, event_type, outcome in (
            (_FAILED, AUTH_FAILURE, OUTCOME_FAILURE),
            (_ACCEPTED, AUTH_SUCCESS, OUTCOME_SUCCESS),
            (_INVALID_USER, INVALID_USER, None),
        ):
            found = pattern.match(message)
            if found is None:
                continue
            ip = found.group("ip")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return _dead(raw, source_id, offset, f"source address is not an IP: {ip!r}")
            groups = found.groupdict()
            pid = match.group("pid")
            extra = {"pid": int(pid) if pid else None}
            if groups.get("port"):
                extra["port"] = int(groups["port"])
            if "method" in groups:
                extra["method"] = groups["method"]
            extra["invalid_user"] = event_type == INVALID_USER or bool(groups.get("invalid"))
            event = Event(
                id=make_event_id(source_id, offset),
                timestamp=timestamp,
                source=SOURCE,
                event_type=event_type,
                src_ip=ip,
                username=groups["user"] or None,
                host=match.group("host"),
                outcome=outcome,
                raw=raw,
                count=count,
                extra=extra,
                source_id=source_id,
                offset=offset,
            )
            return ParseResult(events=(event,))

        for pattern, reason in _IGNORED:
            if pattern.match(message):
                return ParseResult(ignored=reason)

        return _dead(raw, source_id, offset, "unrecognised sshd message")

    def _timestamp(self, match: "re.Match[str]") -> datetime:
        month = _MONTHS.get(match.group("mon"))
        if month is None:
            raise ValueError(f"unknown month {match.group('mon')!r}")
        if self._last_month is not None and self._last_month - month >= 6:
            self._year += 1  # December -> January rollover
        self._last_month = month
        hour, minute, second = (int(part) for part in match.group("time").split(":"))
        # Built explicitly with the tracked year so Feb 29 resolves correctly
        # (strptime without a year would reject it).
        naive = datetime(self._year, month, int(match.group("day")), hour, minute, second)
        return naive.replace(tzinfo=self._tz).astimezone(timezone.utc)


def _iso_timestamp(match: "re.Match[str]") -> datetime:
    base = datetime.strptime(match.group("dt"), "%Y-%m-%dT%H:%M:%S")
    fraction = match.group("frac")
    microsecond = int((fraction[1:] + "000000")[:6]) if fraction else 0
    zone = match.group("tz")
    if zone == "Z":
        offset = timedelta(0)
    else:
        digits = zone[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        if zone[0] == "-":
            offset = -offset
    return base.replace(microsecond=microsecond, tzinfo=timezone(offset)).astimezone(timezone.utc)


def _dead(raw: str, source_id: str, offset: int, reason: str) -> ParseResult:
    return ParseResult(dead_letter=DeadLetter(source_id=source_id, offset=offset, raw=raw, reason=reason))
