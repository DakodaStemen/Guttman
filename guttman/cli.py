"""guttman command line."""
import argparse
import datetime
import json
import os
import sys

from guttman import __version__
from guttman.detect import analyze_path, blocking
from guttman.patterns import LEGACY_METHODS, METHODS, random_passes
from guttman.progress import Progress
from guttman.shredder import IO_MODES, Shredder

EXIT_OK, EXIT_FAIL, EXIT_REFUSED, EXIT_INTERRUPTED = 0, 1, 2, 130

EPILOG = """\
Best-effort tool. Overwriting cannot work on SSD/NVMe, copy-on-write
filesystems (btrfs, ZFS) or storage guttman cannot identify: it REFUSES those
by default (override: --force-unsafe). `guttman advise PATH|DEVICE` prints the
whole-device commands that do work (nvme sanitize, hdparm --security-erase,
blkdiscard -s, cryptsetup luksErase). Nothing is executed.

exit codes: 0 ok | 1 failure (incl. read-back mismatch) | 2 refused by storage
policy or --strict | 130 interrupted
"""

NOTE = ("A read-back check confirms what the OS/device returned. It is not evidence "
        "of physical erasure on flash, copy-on-write or remapped storage.")


def build_parser():
    p = argparse.ArgumentParser(
        prog="guttman",
        description="Best-effort secure file shredder for Linux with read-back "
                    "verification and storage-aware warnings. (Also: `guttman advise "
                    "PATH|DEVICE` for whole-device sanitization commands.)",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-m", "--method", choices=["dod", "random", "gutmann"],
                   default="dod",
                   help="overwrite method (default: dod). 'gutmann' is LEGACY: 35 passes "
                        "aimed at 1990s MFM/RLL drives; no benefit on modern media")
    p.add_argument("-p", "--passes", type=int, default=3, metavar="N",
                   help="pass count for --method=random (default: 3)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--readback", "--readback-check", dest="readback", action="store_true",
                   help="read-back check: after every pass (random included) read the file "
                        "back and compare with what was written")
    p.add_argument("--verify", dest="readback", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="show what would happen and any storage warnings/refusals; change nothing")
    p.add_argument("--progress", action=argparse.BooleanOptionalAction, default=None,
                   help="progress bar on stderr (default: on when stderr is a terminal)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress warnings and notes (refusals are never suppressed)")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="recursively shred a directory")
    p.add_argument("--force-unsafe", action="store_true",
                   help="shred even on SSD/NVMe, copy-on-write or unidentified storage "
                        "(overwrite is NOT reliable there)")
    p.add_argument("--strict", action="store_true",
                   help="treat any warning as failure: nothing is shredded for a target "
                        "with a warning, and the exit code is 2 (wins over --force-unsafe)")
    p.add_argument("--report", metavar="FILE",
                   help="write a JSON report of what was done ('-' for stdout)")
    p.add_argument("--io", choices=IO_MODES, default="sync",
                   help="write mode: buffered | sync (O_SYNC, default) | direct "
                        "(O_DIRECT+O_SYNC, falls back to sync if unsupported)")
    p.add_argument("--no-scrub-names", action="store_true",
                   help="do not rename files to random names before unlinking")
    p.add_argument("--version", action="version", version=f"guttman {__version__}")
    p.add_argument("files", nargs="+", metavar="FILE")
    return p


def _finding_dict(f):
    return {"level": f.level, "code": f.code, "message": f.message}


def _write_report(path, report):
    text = json.dumps(report, indent=2, sort_keys=False) + "\n"
    if path == "-":
        sys.stdout.write(text)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "advise":   # to shred a file literally named "advise": ./advise
        from guttman import advise
        return advise.main(argv[1:])

    args = build_parser().parse_args(argv)

    if args.method == "random":
        if args.passes < 1:
            print("guttman: --passes must be >= 1", file=sys.stderr)
            return EXIT_FAIL
        passes = random_passes(args.passes)
    else:
        passes = METHODS[args.method]()
    if args.method in LEGACY_METHODS and not args.quiet:
        print(f"guttman: note: method '{args.method}' is legacy (aimed at 1990s MFM/RLL "
              "drives); it adds time, not security, on modern media.", file=sys.stderr)

    show = args.progress if args.progress is not None else sys.stderr.isatty()
    shredder = Shredder(
        verbose=args.verbose, verify=args.readback, dry_run=args.dry_run,
        progress=Progress() if show and not args.dry_run else None,
        scrub_names=not args.no_scrub_names, io_mode=args.io,
    )
    errors = refused = 0
    results = []
    rc = None

    try:
        for target in args.files:
            res = {"target": target, "status": "failed", "findings": []}
            results.append(res)
            if not os.path.exists(target) and not os.path.islink(target):
                print(f"guttman: {target}: no such file or directory", file=sys.stderr)
                res["error"] = "no such file or directory"
                errors += 1
                continue

            findings = analyze_path(target)
            res["findings"] = [_finding_dict(f) for f in findings]
            blockers = blocking(findings)
            warns = [f for f in findings if f.level == "warn"]

            if blockers and not args.force_unsafe:
                res["status"] = "refused"
                refused += 1
                verb = "would refuse" if args.dry_run else "refusing"
                for f in blockers:
                    print(f"guttman: {verb}: {target}: {f.message}", file=sys.stderr)
                print(f"guttman: {target}: overwriting is not reliable here. Run "
                      f"`guttman advise {target}` for what to do instead, or pass "
                      "--force-unsafe to shred anyway.", file=sys.stderr)
                continue
            if args.strict and warns:
                res["status"] = "refused"
                refused += 1
                for f in warns:
                    print(f"guttman: --strict: {target}: {f.message}", file=sys.stderr)
                continue
            if not args.quiet:
                for f in findings:
                    if f.level == "warn":
                        extra = " (proceeding: --force-unsafe)" if f in blockers else ""
                        print(f"guttman: warning: {target}: {f.message}{extra}", file=sys.stderr)
                    elif f.code == "journal":
                        print(f"guttman: note: {target}: {f.message}", file=sys.stderr)

            first = len(shredder.records)
            try:
                if os.path.isdir(target) and not os.path.islink(target):
                    if not args.recursive:
                        print(f"guttman: {target}: is a directory (use -r)", file=sys.stderr)
                        res["error"] = "is a directory (use -r)"
                        errors += 1
                        continue
                    if args.verbose:
                        print(f"shredding directory: {target}")
                    n = shredder.shred_directory(target, passes)
                    errors += n
                    res["status"] = "dry-run" if args.dry_run else ("shredded" if n == 0 else "failed")
                else:
                    if args.verbose:
                        print(f"shredding: {target}")
                    shredder.shred(target, passes)
                    res["status"] = shredder.records[-1]["status"]
            except KeyboardInterrupt:
                res["status"] = "interrupted"
                print(
                    f"\ninterrupted mid-shred on {target} - "
                    "file state is indeterminate, do not treat as securely deleted.",
                    file=sys.stderr,
                )
                rc = EXIT_INTERRUPTED
                break
            except Exception as exc:
                print(f"guttman: {target}: {exc}", file=sys.stderr)
                res["error"] = str(exc)
                errors += 1
            finally:
                res["files"] = shredder.records[first:]
    finally:
        if args.report:
            report = {
                "tool": "guttman",
                "version": __version__,
                "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "method": args.method,
                "legacy_method": args.method in LEGACY_METHODS,
                "passes": len(passes),
                "options": {"dry_run": args.dry_run, "readback_check": args.readback,
                            "io": args.io, "scrub_names": not args.no_scrub_names,
                            "force_unsafe": args.force_unsafe, "strict": args.strict},
                "results": results,
                "summary": {"targets": len(results), "refused": refused, "errors": errors,
                            "engine_warnings": shredder.warnings},
                "note": NOTE,
            }
            try:
                _write_report(args.report, report)
            except OSError as exc:
                print(f"guttman: cannot write report: {exc}", file=sys.stderr)
                errors += 1

    if rc is not None:
        return rc
    if args.strict and shredder.warnings:
        print("guttman: --strict: warnings were raised during shredding", file=sys.stderr)
        return EXIT_REFUSED
    if refused:
        return EXIT_REFUSED
    return EXIT_OK if errors == 0 else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
