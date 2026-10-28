#!/usr/bin/env python3
"""Measure real shred throughput per method. Temp files only.

usage: python benchmarks/bench.py [--size-mib 64] [--runs 3] [--dir DIR]
Prints a Markdown table. "effective" = file size / wall time (what a user
experiences); "raw write" = bytes written (size x passes) / wall time.
"""
import argparse
import os
import platform
import statistics
import tempfile
import time

from guttman.patterns import dod_passes, gutmann_passes, random_passes
from guttman.shredder import Shredder

METHODS = [
    ("dod", dod_passes),
    ("dod + verify", dod_passes),
    ("random x3", lambda: random_passes(3)),
    ("gutmann", gutmann_passes),
    ("gutmann + verify", gutmann_passes),
]


def run(size, make, verify, d):
    fd, path = tempfile.mkstemp(dir=d)
    os.write(fd, os.urandom(1 << 20) * (size >> 20))
    os.close(fd)
    passes = make()
    t = time.perf_counter()
    Shredder(verify=verify).shred(path, passes)
    return time.perf_counter() - t, len(passes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--size-mib", type=int, default=64)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--dir", default=None)
    a = ap.parse_args()
    size = a.size_mib << 20
    with tempfile.TemporaryDirectory(dir=a.dir) as d:
        print(f"<!-- {platform.platform()} | python {platform.python_version()} | "
              f"{a.size_mib} MiB file | median of {a.runs} | dir={d} -->")
        print("| Method | Passes | Median time | Effective MiB/s | Raw write MiB/s |")
        print("|---|---|---|---|---|")
        for name, make in METHODS:
            verify = "verify" in name
            res = [run(size, make, verify, d) for _ in range(a.runs)]
            t = statistics.median(r[0] for r in res)
            n = res[0][1]
            eff = a.size_mib / t
            print(f"| {name} | {n} | {t:.2f} s | {eff:.0f} | {eff * n:.0f} |")


if __name__ == "__main__":
    main()
