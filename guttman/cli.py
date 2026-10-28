"""guttman command line."""
import argparse
import os
import sys

from guttman import __version__
from guttman.detect import analyze_path
from guttman.patterns import METHODS, random_passes
from guttman.progress import Progress
from guttman.shredder import Shredder

EPILOG = """\
Overwrite-based deletion cannot guarantee erasure on SSDs, copy-on-write
filesystems (btrfs, ZFS) or journaled data. guttman warns when it detects
these; for strong guarantees use full-disk encryption and destroy the key.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="guttman",
        description="Secure file deletion via multi-pass overwrite "
                    "(DoD 5220.22-M, Gutmann 35-pass, random).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-m", "--method", choices=["dod", "gutmann", "random"],
                   default="dod", help="overwrite method (default: dod)")
    p.add_argument("-p", "--passes", type=int, default=3, metavar="N",
                   help="pass count for --method=random (default: 3)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--verify", action="store_true",
                   help="read back every pass (random included) and confirm it matches")
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="show what would happen and any storage warnings; change nothing")
    p.add_argument("--progress", action=argparse.BooleanOptionalAction, default=None,
                   help="progress bar on stderr (default: on when stderr is a terminal)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress storage-risk warnings")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="recursively shred a directory")
    p.add_argument("--version", action="version", version=f"guttman {__version__}")
    p.add_argument("files", nargs="+", metavar="FILE")
    return p


def _report_findings(target, quiet):
    if quiet:
        return
    for f in analyze_path(target):
        if f.level == "warn":
            print(f"guttman: warning: {target}: {f.message}", file=sys.stderr)
        elif f.code in ("journal",):
            print(f"guttman: note: {target}: {f.message}", file=sys.stderr)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.method == "random":
        if args.passes < 1:
            print("guttman: --passes must be >= 1", file=sys.stderr)
            return 1
        passes = random_passes(args.passes)
    else:
        passes = METHODS[args.method]()

    show = args.progress if args.progress is not None else sys.stderr.isatty()
    shredder = Shredder(
        verbose=args.verbose, verify=args.verify, dry_run=args.dry_run,
        progress=Progress() if show and not args.dry_run else None,
    )
    errors = 0

    for target in args.files:
        if not os.path.exists(target) and not os.path.islink(target):
            print(f"guttman: {target}: no such file or directory", file=sys.stderr)
            errors += 1
            continue

        try:
            _report_findings(target, args.quiet)
            if os.path.isdir(target) and not os.path.islink(target):
                if not args.recursive:
                    print(f"guttman: {target}: is a directory (use -r)", file=sys.stderr)
                    errors += 1
                    continue
                if args.verbose:
                    print(f"shredding directory: {target}")
                errors += shredder.shred_directory(target, passes)
            else:
                if args.verbose:
                    print(f"shredding: {target}")
                shredder.shred(target, passes)
        except KeyboardInterrupt:
            print(
                f"\ninterrupted mid-shred on {target} - "
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
