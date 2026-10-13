"""CLI: python -m siftlog.enrich --db siftlog.db (--geoip GeoLite2-City.mmdb | --simulated)"""
from __future__ import annotations

import argparse
from typing import List, Optional

from siftlog.enrich.geo import TableGeoResolver, open_maxmind
from siftlog.store import EventStore


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.enrich",
        description="Add locations to stored events that do not have one yet. Safe to re-run.",
    )
    parser.add_argument("--db", default="siftlog.db")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--geoip", metavar="FILE.mmdb", help="a MaxMind GeoLite2-City database")
    source.add_argument("--simulated", action="store_true",
                        help="the simulator's fake location table (for logs made by siftlog.simulator)")
    args = parser.parse_args(argv)

    if args.simulated:
        from siftlog.simulator import FAKE_GEO

        resolver = TableGeoResolver(FAKE_GEO)
    else:
        try:
            resolver = open_maxmind(args.geoip)
        except (RuntimeError, OSError) as exc:
            parser.error(str(exc))

    with EventStore(args.db) as store:
        located, addresses = store.backfill_geo(resolver)
    print(f"{args.db}: located {located} event(s) across {addresses} address(es)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
