#!/usr/bin/env python3
"""
guttman - secure file deletion via multi-pass overwrite

Rewrites file contents with byte patterns before unlinking the inode.
Supports DoD 5220.22-M, Gutmann 35-pass, and configurable random passes.

Note: on SSDs and copy-on-write filesystems (btrfs, ZFS), overwrite-based
deletion cannot guarantee physical sector erasure. Use full-disk encryption
if that threat model applies to you.
"""
import argparse
import os
import sys

from patterns import dod_passes, gutmann_passes, random_passes
from shredder import Shredder


def build_parser():
    p = argparse.ArgumentParser(
        prog="guttman",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-m", "--method",
        choices=["dod", "gutmann", "random"],
        default="dod",
        help="overwrite method (default: dod)",
    )
    p.add_argument(
        "-p", "--passes",
        type=int,
        default=3,
        metavar="N",
        help="pass count for --method=random (default: 3)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--verify", action="store_true",
                   help="read back and verify each deterministic pass")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="recursively shred a directory")
    p.add_argument("files", nargs="+", metavar="FILE")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.method == "dod":
        passes = dod_passes()
    elif args.method == "gutmann":
        passes = gutmann_passes()
    else:
        if args.passes < 1:
            print("guttman: --passes must be >= 1", file=sys.stderr)
            return 1
        passes = random_passes(args.passes)

    shredder = Shredder(verbose=args.verbose, verify=args.verify)
    errors = 0

    for target in args.files:
        if not os.path.exists(target) and not os.path.islink(target):
            print(f"guttman: {target}: no such file or directory", file=sys.stderr)
            errors += 1
            continue

        try:
            if os.path.isdir(target):
                if not args.recursive:
                    print(
                        f"guttman: {target}: is a directory (use -r)",
                        file=sys.stderr,
                    )
                    errors += 1
                    continue
                if args.verbose:
                    print(f"shredding directory: {target}")
                shredder.shred_directory(target, passes)
            else:
                if args.verbose:
                    print(f"shredding: {target}")
                shredder.shred(target, passes)
        except KeyboardInterrupt:
            print(
                f"\ninterrupted mid-shred on {target} — "
                "file state is indeterminate, do not treat as securely deleted.",
                file=sys.stderr,
            )
            return 130
        except Exception as exc:
            print(f"guttman: {target}: {exc}", file=sys.stderr)
            errors += 1

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
