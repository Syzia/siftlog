"""Log parsers. One module per source; each turns raw lines into Events."""
from typing import Dict, Type

from siftlog.parsers.sshd import SshdParser

# Registered by name, so the ingest CLI and later stages can pick a parser from config.
PARSERS: Dict[str, Type[SshdParser]] = {"sshd": SshdParser}

__all__ = ["PARSERS", "SshdParser"]
