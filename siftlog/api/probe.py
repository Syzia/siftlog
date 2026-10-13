"""Is the honeypot up? A reachability check on its two ports.

The target is only ever the host in the local settings file. Nothing in a
request can choose where this connects, so it cannot be used to scan other
machines from this one.

It runs only when asked, and the answer is kept for a minute. Each check is a
real connection to the honeypot, which Cowrie logs like any other visitor, so
checking on a timer would fill the honeypot's own data with this machine's
address.
"""
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

CACHE_SECONDS = 60.0
HONEYPOT_PORT = 22


def read_banner(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """Connect and read the first line the server sends, if any."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            try:
                data = conn.recv(160)
            except OSError:  # connected, but it said nothing in time
                data = b""
    except OSError:
        return {"port": port, "open": False, "banner": ""}
    first_line = data.split(b"\n", 1)[0].decode("ascii", errors="replace")
    banner = "".join(ch for ch in first_line if ch.isprintable())[:80].strip()
    return {"port": port, "open": True, "banner": banner}


class HoneypotProbe:
    def __init__(
        self,
        host: Optional[str],
        admin_port: int,
        *,
        honeypot_port: int = HONEYPOT_PORT,
        clock: Callable[[], float] = time.monotonic,
        reader: Callable[..., Dict[str, Any]] = read_banner,
    ) -> None:
        self._host = host
        self._ports = [(honeypot_port, "honeypot"), (admin_port, "admin")]
        self._clock = clock
        self._reader = reader
        self._lock = threading.Lock()
        self._checked_at: Optional[float] = None
        self._result: Dict[str, Any] = self._blank()

    def _blank(self) -> Dict[str, Any]:
        return {"configured": self._host is not None, "host": self._host, "checked_at": None, "checks": []}

    def last(self) -> Dict[str, Any]:
        """The most recent result, without connecting to anything."""
        with self._lock:
            return dict(self._result)

    def check(self) -> Dict[str, Any]:
        """Check now, unless it was checked within the last minute."""
        if self._host is None:
            return self._blank()
        with self._lock:
            now = self._clock()
            if self._checked_at is not None and now - self._checked_at < CACHE_SECONDS:
                return dict(self._result)
            checks: List[Dict[str, Any]] = []
            for port, role in self._ports:
                outcome = self._reader(self._host, port)
                outcome["role"] = role
                checks.append(outcome)
            self._checked_at = now
            self._result = {
                "configured": True,
                "host": self._host,
                "checked_at": datetime.now(timezone.utc),
                "checks": checks,
            }
            return dict(self._result)
