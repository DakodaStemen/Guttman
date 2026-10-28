"""Core overwrite engine."""
import hashlib
import os
import stat
import sys
from dataclasses import dataclass

from guttman.patterns import RANDOM, _tile

# 768 KiB. Must be a multiple of 3 so the 3-byte Gutmann patterns stay in
# phase from one block to the next (a power-of-two block would restart the
# pattern mid-cycle at every block boundary).
BLOCK = 3 * 2**18


class VerifyError(Exception):
    """Read-back did not match what was written."""


@dataclass
class Plan:
    path: str
    size: int
    passes: int
    verify: bool
    is_symlink: bool = False

    @property
    def bytes_written(self) -> int:
        return 0 if self.is_symlink else self.size * self.passes

    @property
    def bytes_read(self) -> int:
        return self.bytes_written if self.verify else 0


class Shredder:
    def __init__(self, verbose=False, verify=False, dry_run=False, progress=None):
        self.verbose = verbose
        self.verify = verify
        self.dry_run = dry_run
        self.progress = progress

    # ------------------------------------------------------------------
    def plan(self, path: str, passes: list) -> Plan:
        if os.path.islink(path):
            return Plan(path, 0, len(passes), self.verify, is_symlink=True)
        return Plan(path, os.stat(path).st_size, len(passes), self.verify)

    def shred(self, path: str, passes: list) -> None:
        # A symlink is removed, never followed: overwriting the target would
        # destroy data the user did not name.
        if os.path.islink(path):
            if self.dry_run:
                print(f"[dry-run] would unlink symlink {path} (target untouched)")
                return
            os.unlink(path)
            if self.verbose:
                print(f"  {path}: symlink removed (target untouched)")
            return

        st = os.stat(path)
        size = st.st_size

        if st.st_nlink > 1:
            print(
                f"guttman: warning: {path} has {st.st_nlink} hard links; "
                "all of them see the overwritten data",
                file=sys.stderr,
            )

        if self.dry_run:
            p = self.plan(path, passes)
            print(
                f"[dry-run] would shred {path}: {size} bytes x {p.passes} passes"
                f"{' + verify' if self.verify else ''} "
                f"= {p.bytes_written} bytes written, {p.bytes_read} read"
            )
            return

        # read-only files are common in archived directories
        restore_mode = None
        if not os.access(path, os.W_OK):
            restore_mode = stat.S_IMODE(st.st_mode)
            os.chmod(path, restore_mode | stat.S_IWUSR)

        if size == 0:
            if self.verbose:
                print(f"  {path}: empty, skipping passes")
            os.unlink(path)
            return

        if self.progress:
            self.progress.start_file(path)
        ok = False
        try:
            fd = os.open(path, os.O_RDWR)
        except OSError as exc:
            print(f"guttman: cannot open {path}: {exc}", file=sys.stderr)
            if restore_mode is not None:
                os.chmod(path, restore_mode)
            raise

        try:
            for i, pat in enumerate(passes):
                label = "random" if pat is RANDOM else pat.hex()
                if self.verbose:
                    print(f"  {path}: pass {i + 1}/{len(passes)} [{label}]")
                digest = self._write_pass(fd, size, pat, i + 1, len(passes), path)
                if self.verify:
                    self._verify_pass(fd, size, digest, i + 1, len(passes), path)
                    if self.verbose:
                        print(f"  {path}: pass {i + 1} verified")
            os.ftruncate(fd, 0)
            os.fsync(fd)
            ok = True
        finally:
            os.close(fd)
            if self.progress:
                self.progress.finish_file(path, ok)

        os.unlink(path)
        if self.verbose:
            print(f"  {path}: deleted")

    # ------------------------------------------------------------------
    def _write_pass(self, fd, size, pat, pass_no=1, n_passes=1, path=""):
        os.lseek(fd, 0, os.SEEK_SET)
        h = hashlib.blake2b(digest_size=16)
        fixed = None if pat is RANDOM else _tile(pat, BLOCK)
        written = 0
        while written < size:
            n = min(BLOCK, size - written)
            if pat is RANDOM:
                buf = os.urandom(n)
            else:
                buf = fixed if n == BLOCK else fixed[:n]
            view = memoryview(buf)
            off = 0
            while off < n:  # os.write may be short
                off += os.write(fd, view[off:])
            h.update(buf)
            written += n
            if self.progress:
                self.progress.update(path, pass_no, n_passes, "write", written, size, n)
        os.fsync(fd)
        return h.digest()

    def _verify_pass(self, fd, size, expected, pass_no=1, n_passes=1, path=""):
        # Drop cached pages so the read-back hits the device, not RAM.
        # Best effort: some filesystems ignore the hint.
        if hasattr(os, "posix_fadvise"):
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        os.lseek(fd, 0, os.SEEK_SET)
        h = hashlib.blake2b(digest_size=16)
        offset = 0
        while offset < size:
            got = os.read(fd, min(BLOCK, size - offset))
            if not got:
                raise VerifyError(f"pass {pass_no}: short read at byte {offset}")
            h.update(got)
            offset += len(got)
            if self.progress:
                self.progress.update(path, pass_no, n_passes, "verify", offset, size, len(got))
        if h.digest() != expected:
            raise VerifyError(f"pass {pass_no}: read-back mismatch ({path})")

    # ------------------------------------------------------------------
    def shred_directory(self, path: str, passes: list) -> int:
        """Shred everything under path. Returns the number of failures."""
        failures = 0
        for dirpath, dirs, files in os.walk(path, topdown=False):
            # symlinks to directories show up in dirs; treat them as links
            for d in dirs:
                dp = os.path.join(dirpath, d)
                if os.path.islink(dp):
                    files = files + [d]
            for fname in files:
                fpath = os.path.join(dirpath, fname)
                try:
                    self.shred(fpath, passes)
                except Exception as exc:
                    failures += 1
                    print(f"guttman: error: {fpath}: {exc}", file=sys.stderr)
            if self.dry_run:
                continue
            try:
                os.rmdir(dirpath)
                if self.verbose:
                    print(f"  {dirpath}: removed")
            except OSError as exc:
                failures += 1
                print(f"guttman: error: could not remove {dirpath}: {exc}", file=sys.stderr)
        return failures
