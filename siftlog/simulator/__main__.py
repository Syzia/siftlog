"""CLI: python -m siftlog.simulator --seed 1 --out sim.log"""
from __future__ import annotations

import argparse
from typing import List, Optional

from siftlog.simulator.core import simulate, write_files


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.simulator",
        description="Generate a deterministic SSH auth log plus a ground-truth label file.",
    )
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--format", choices=("syslog", "iso"), default="syslog")
    parser.add_argument("--hours", type=float, default=48, help="length of the simulated window")
    parser.add_argument("--out", default="simulated-auth.log", help="log file to write")
    parser.add_argument("--labels", default=None, help="label JSON path (default: <out>.labels.json)")
    args = parser.parse_args(argv)

    sim = simulate(seed=args.seed, fmt=args.format, duration_hours=args.hours)
    labels_path = args.labels or args.out + ".labels.json"
    write_files(sim, args.out, labels_path)
    print(f"wrote {len(sim.lines)} lines, {len(sim.labels)} scenarios -> {args.out}, {labels_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
