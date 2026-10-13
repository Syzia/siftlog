"""Log parsers. One module per source; each turns raw lines into Events."""
import ipaddress
from datetime import timezone, tzinfo
from typing import Any, Dict, Iterable, Mapping, Optional

from siftlog.events import ParseResult
from siftlog.parsers.cowrie import CowrieParser
from siftlog.parsers.sshd import SshdParser

# Registered by name, so the command-line tools can pick a parser with --source.
PARSERS: Dict[str, Any] = {"sshd": SshdParser, "cowrie": CowrieParser}

OWN_ADDRESS = "own-address"


class ParserConfigError(ValueError):
    """The options given cannot build a parser. The message says why."""


class SkipAddresses:
    """Wraps a parser and leaves out lines from addresses the operator names as their own.

    A honeypot's log includes its owner's own test logins. Stored as events they
    would raise alerts about the owner. The lines are counted as ignored (reason
    ``own-address``), never as dead letters: they were understood.
    """

    def __init__(self, parser: Any, addresses: Iterable[str]) -> None:
        self._parser = parser
        self.source = parser.source
        self.needs_year = parser.needs_year
        self._networks = []
        for text in addresses:
            try:
                self._networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError as exc:
                raise ParserConfigError(f"not an IP address or network: {text!r}") from exc

    def state(self) -> Mapping[str, Any]:
        return self._parser.state()

    def restore(self, state: Mapping[str, Any]) -> None:
        self._parser.restore(state)

    def _own(self, src_ip: Optional[str]) -> bool:
        if src_ip is None:
            return False
        try:
            address = ipaddress.ip_address(src_ip)
        except ValueError:
            return False
        return any(address in network for network in self._networks)

    def parse_line(self, line: str, source_id: str, offset: int) -> ParseResult:
        result = self._parser.parse_line(line, source_id, offset)
        if result.events and all(self._own(event.src_ip) for event in result.events):
            return ParseResult(ignored=OWN_ADDRESS)
        return result


def build_parser(
    source: str,
    *,
    year: Optional[int] = None,
    tz: tzinfo = timezone.utc,
    ignore_ips: Iterable[str] = (),
) -> Any:
    """A fresh parser for ``source``. Raises ParserConfigError if the options do not fit it."""
    if source not in PARSERS:
        raise ParserConfigError(f"unknown source {source!r}; choose from {', '.join(sorted(PARSERS))}")
    parser_class = PARSERS[source]
    if parser_class.needs_year and year is None:
        raise ParserConfigError(
            f"--year is required for --source {source}: its timestamps have no year, "
            "and guessing would silently corrupt every timestamp"
        )
    parser = parser_class(year=year, tz=tz)
    ignore_ips = list(ignore_ips)
    return SkipAddresses(parser, ignore_ips) if ignore_ips else parser


__all__ = ["PARSERS", "CowrieParser", "ParserConfigError", "SkipAddresses", "SshdParser", "build_parser"]
