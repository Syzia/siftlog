"""CLI: python -m siftlog.api --db siftlog.db --rules rules

The token comes from the SIFTLOG_API_TOKEN environment variable. Without it a
random one is generated for this run and printed once.
"""
import argparse
import os
import secrets
import sys
import threading
import webbrowser
from typing import List, NamedTuple, Optional
from urllib.parse import quote

from fastapi import FastAPI

from siftlog.api.app import create_app
from siftlog.api.local import LOCAL_CONFIG, LocalConfigError, load_local_config
from siftlog.engine import RuleError, load_rules

TOKEN_ENV = "SIFTLOG_API_TOKEN"
LOOPBACK = ("127.0.0.1", "localhost", "::1")


class Server(NamedTuple):
    app: FastAPI
    host: str
    port: int
    # Opens the dashboard already signed in. The token is in the URL *fragment*, the
    # part after #, which a browser never sends to a server and which never appears
    # in a request log. The page reads it once and removes it from the address bar.
    signed_in_url: str
    open_browser: bool


def build(argv: Optional[List[str]] = None) -> Server:
    """Parse arguments and construct the app."""
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.api",
        description="Serve events and alerts over HTTP. Every route except /health needs a bearer token.",
    )
    parser.add_argument("--db", default="siftlog.db")
    parser.add_argument("--rules", default="rules", help="rule file or directory (for the /rules listing)")
    parser.add_argument("--host", default="127.0.0.1", help="address to bind (default: this machine only)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--open", action="store_true", help="open the dashboard in your browser, already signed in")
    parser.add_argument(
        "--local-config",
        default=LOCAL_CONFIG,
        help=f"this machine's own settings, such as the honeypot's address (default: {LOCAL_CONFIG} if present)",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.db):
        # Opening a missing path would silently create an empty database and serve it.
        parser.error(f"database not found: {args.db} (create it with python -m siftlog.ingest)")
    try:
        rules = load_rules(args.rules)
        local = load_local_config(args.local_config)
    except (RuleError, LocalConfigError, OSError) as exc:
        parser.error(str(exc))

    token = os.environ.get(TOKEN_ENV, "")
    if args.host not in LOOPBACK:
        if not token:
            parser.error(
                f"refusing to listen on {args.host} with a generated token: set {TOKEN_ENV} yourself, "
                "and put a TLS-terminating proxy in front, because this server speaks plain HTTP"
            )
        print(f"warning: listening on {args.host} over plain HTTP; the token is sent unencrypted", file=sys.stderr)
    generated = not token
    if generated:
        token = secrets.token_urlsafe(32)
    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    base = f"http://{shown_host}:{args.port}/dashboard/"
    signed_in_url = f"{base}#token={quote(token, safe='')}"
    if generated:
        # Printed only for a token made up for this run. One the operator chose is theirs to keep.
        print(f"API token for this run (set {TOKEN_ENV} to choose your own): {token}", file=sys.stderr)
        print(f"Dashboard, already signed in: {signed_in_url}", file=sys.stderr)
    else:
        print(f"Dashboard: {base} (sign in with your {TOKEN_ENV})", file=sys.stderr)
    app = create_app(
        args.db, rules, token, local=local, project_dir=os.getcwd(), rules_path=args.rules
    )
    return Server(app, args.host, args.port, signed_in_url, args.open)


def main(argv: Optional[List[str]] = None) -> int:
    import uvicorn

    server = build(argv)
    if server.open_browser:
        # A moment after the server starts listening, so the page is there when the browser asks.
        threading.Timer(1.0, webbrowser.open, [server.signed_in_url]).start()
    uvicorn.run(server.app, host=server.host, port=server.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
