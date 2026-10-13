"""CLI: python -m siftlog.api --db siftlog.db --rules rules

The token comes from the SIFTLOG_API_TOKEN environment variable. Without it a
random one is generated for this run and printed once.
"""
import argparse
import os
import secrets
import sys
from typing import List, Optional, Tuple

from fastapi import FastAPI

from siftlog.api.app import create_app
from siftlog.engine import RuleError, load_rules

TOKEN_ENV = "SIFTLOG_API_TOKEN"
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def build(argv: Optional[List[str]] = None) -> Tuple[FastAPI, str, int]:
    """Parse arguments and construct the app. Returns (app, host, port)."""
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.api",
        description="Serve events and alerts over HTTP. Every route except /health needs a bearer token.",
    )
    parser.add_argument("--db", default="siftlog.db")
    parser.add_argument("--rules", default="rules", help="rule file or directory (for the /rules listing)")
    parser.add_argument("--host", default="127.0.0.1", help="address to bind (default: this machine only)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    if not os.path.exists(args.db):
        # Opening a missing path would silently create an empty database and serve it.
        parser.error(f"database not found: {args.db} (create it with python -m siftlog.ingest)")
    try:
        rules = load_rules(args.rules)
    except (RuleError, OSError) as exc:
        parser.error(str(exc))

    token = os.environ.get(TOKEN_ENV, "")
    if args.host not in LOOPBACK:
        if not token:
            parser.error(
                f"refusing to listen on {args.host} with a generated token: set {TOKEN_ENV} yourself, "
                "and put a TLS-terminating proxy in front, because this server speaks plain HTTP"
            )
        print(f"warning: listening on {args.host} over plain HTTP; the token is sent unencrypted", file=sys.stderr)
    if not token:
        token = secrets.token_urlsafe(32)
        print(f"API token for this run (set {TOKEN_ENV} to choose your own): {token}", file=sys.stderr)
    return create_app(args.db, rules, token), args.host, args.port


def main(argv: Optional[List[str]] = None) -> int:
    import uvicorn

    app, host, port = build(argv)
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
