"""Log parsers. One module per source; each turns raw lines into Events."""
from siftlog.parsers.sshd import SshdParser

__all__ = ["SshdParser"]
