"""Core overwrite engine."""
import errno
import hashlib
import mmap
import os
import secrets
import stat
import sys
from dataclasses import dataclass

from guttman.patterns import RANDOM, _tile

# 768 KiB. Must be a multiple of 3 so the 3-byte Gutmann patterns stay in
# phase from one block to the next (a power-of-two block would restart the
# pattern mid-cycle at every block boundary). Also a multiple of 4096, so
# full blocks are valid O_DIRECT transfers.
BLOCK = 3 * 2**18
ALIGN = 4096

# buffered: plain writes + fsync per pass
# sync:     O_SYNC (each write returns only when the device acknowledged it)
# direct:   O_DIRECT + O_SYNC where the filesystem allows it (bypasses the
#           page cache for aligned I/O; falls back to sync, and says so)
IO_MODES = ("buffered", "sync", "direct")

NAME_ROUNDS = 3


class ReadbackError(Exception):
    """Read-back did not match what was written."""


# Backwards-compatible name.
VerifyError = ReadbackError


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
    """`verify` is the internal name of the read-back check (CLI: --readback)."""

    def __init__(self, verbose=False, verify=False, dry_run=False, progress=None,
                 scrub_names=True, io_mode="sync"):
        if io_mode not in IO_MODES:
            raise ValueError(f"io_mode must be one of {IO_MODES}")
        self.verbose = verbose
        self.verify = verify
        self.dry_run = dry_run
        self.progress = progress
        self.scrub_names = scrub_names
        self.io_mode = io_mode
        self.records = []      # one dict per path processed (for --report)
        self.warnings = 0      # warnings raised by the engine itself
        self._dfd = None       # O_DIRECT descriptor, when active
        self._abuf = None      # page-aligned buffer for O_DIRECT

    # ------------------------------------------------------------------
    def plan(self, path: str, passes: list) -> Plan:
        if os.path.islink(path):
            return Plan(path, 0, len(passes), self.verify, is_symlink=True)
        return Plan(path, os.stat(path).st_size, len(passes), self.verify)

    def _warn(self, msg):
        self.warnings += 1
        print(f"guttman: warning: {msg}", file=sys.stderr)

    def shred(self, path: str, passes: list) -> None:
        rec = {"path": path, "status": "failed", "passes": len(passes),
               "readback_checked": False, "renamed": False}
        self.records.append(rec)
        try:
            self._shred(path, passes, rec)
        except BaseException as exc:
            rec["status"] = "failed"
            rec["error"] = f"{type(exc).__name__}: {exc}"
            raise

    def _shred(self, path, passes, rec):
        # A symlink is removed, never followed: overwriting the target would
        # destroy data the user did not name.
        if os.path.islink(path):
            rec.update(size=0, bytes_written=0)
            if self.dry_run:
                rec["status"] = "dry-run"
                print(f"[dry-run] would unlink symlink {path} (target untouched)")
                return
            self._remove(path, rec)
            rec["status"] = "symlink-removed"
            if self.verbose:
                print(f"  {path}: symlink removed (target untouched)")
            return

        st = os.stat(path)
        size = st.st_size
        rec["size"] = size
        rec["sparse"] = (st.st_blocks * 512) < size

        if st.st_nlink > 1:
            self._warn(
                f"{path} has {st.st_nlink} hard links; "
                "all of them see the overwritten data"
            )
            rec["hard_links"] = st.st_nlink

        if self.dry_run:
            p = self.plan(path, passes)
            rec.update(status="dry-run", bytes_written=0)
            print(
                f"[dry-run] would shred {path}: {size} bytes x {p.passes} passes"
                f"{' + read-back check' if self.verify else ''} "
                f"= {p.bytes_written} bytes written, {p.bytes_read} read"
                f"{' (sparse: holes are skipped)' if rec['sparse'] else ''}"
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
            rec.update(bytes_written=0, data_bytes=0)
            self._remove(path, rec)
            rec["status"] = "shredded"
            return

        if self.progress:
            self.progress.start_file(path)
        ok = False
        try:
            fd = self._open(path, rec)
        except OSError as exc:
            print(f"guttman: cannot open {path}: {exc}", file=sys.stderr)
            if restore_mode is not None:
                os.chmod(path, restore_mode)
            if self.progress:
                self.progress.finish_file(path, False)
            raise

        try:
            extents = self._extents(fd, size)
            data_bytes = sum(e - s for s, e in extents)
            rec["data_bytes"] = data_bytes
            rec["bytes_written"] = data_bytes * len(passes)
            for i, pat in enumerate(passes):
                label = "random" if pat is RANDOM else pat.hex()
                if self.verbose:
                    print(f"  {path}: pass {i + 1}/{len(passes)} [{label}]")
                digest = self._write_pass(fd, size, pat, i + 1, len(passes), path)
                if self.verify:
                    self._verify_pass(fd, size, digest, i + 1, len(passes), path)
                    rec["readback_checked"] = True
                    if self.verbose:
                        print(f"  {path}: pass {i + 1} read-back OK")
            os.ftruncate(fd, 0)
            os.fsync(fd)
            ok = True
        finally:
            os.close(fd)
            if self._dfd is not None:
                os.close(self._dfd)
                self._dfd = None
            self._abuf = None
            if self.progress:
                self.progress.finish_file(path, ok)

        self._remove(path, rec)
        rec["status"] = "shredded"
        if self.verbose:
            print(f"  {path}: deleted")

    # ------------------------------------------------------------------
    def _open(self, path, rec):
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        if self.io_mode in ("sync", "direct") and hasattr(os, "O_SYNC"):
            flags |= os.O_SYNC
            rec["io"] = "O_SYNC"
        else:
            rec["io"] = "buffered"
        fd = os.open(path, flags)
        self._dfd = None
        if self.io_mode == "direct":
            if hasattr(os, "O_DIRECT"):
                try:
                    self._dfd = os.open(path, flags | os.O_DIRECT)
                    self._abuf = mmap.mmap(-1, BLOCK)  # page-aligned
                    rec["io"] = "O_DIRECT+O_SYNC (aligned I/O)"
                except OSError as exc:
                    self._dfd = None
                    rec["io"] = f"O_SYNC (O_DIRECT unavailable: {errno.errorcode.get(exc.errno, exc.errno)})"
            else:
                rec["io"] = "O_SYNC (O_DIRECT unsupported on this platform)"
            if self._dfd is None:
                print(f"guttman: note: {path}: {rec['io']}", file=sys.stderr)
        return fd

    def _extents(self, fd, size):
        """Allocated (start, end) byte ranges. Holes in sparse files are skipped:
        they hold no data, and writing them would only allocate space."""
        if not hasattr(os, "SEEK_DATA"):
            return [(0, size)]
        out, pos = [], 0
        try:
            while pos < size:
                try:
                    start = os.lseek(fd, pos, os.SEEK_DATA)
                except OSError as exc:
                    if exc.errno == errno.ENXIO:  # no more data
                        break
                    raise
                end = min(os.lseek(fd, start, os.SEEK_HOLE), size)
                if end <= start:
                    break
                out.append((start, end))
                pos = end
        except OSError:
            return [(0, size)]  # filesystem can't tell: treat everything as data
        return out

    def _pwrite(self, fd, buf, off):
        n = len(buf)
        done = 0
        if self._dfd is not None and off % ALIGN == 0 and n % ALIGN == 0:
            self._abuf[:n] = buf
            view = memoryview(self._abuf)[:n]
            while done < n:
                done += os.pwrite(self._dfd, view[done:], off + done)
                if done < n and (off + done) % ALIGN:
                    break  # short write broke alignment; finish buffered
            view.release()
        view = memoryview(buf)
        while done < n:  # os.pwrite may be short
            done += os.pwrite(fd, view[done:], off + done)

    def _pread(self, fd, n, off):
        if self._dfd is not None and off % ALIGN == 0 and n % ALIGN == 0:
            view = memoryview(self._abuf)[:n]
            got = os.preadv(self._dfd, [view], off)
            view.release()
            return bytes(self._abuf[:got])
        return os.pread(fd, n, off)

    def _write_pass(self, fd, size, pat, pass_no=1, n_passes=1, path=""):
        h = hashlib.blake2b(digest_size=16)
        extents = self._extents(fd, size)
        total = sum(e - s for s, e in extents)
        written = 0
        for start, end in extents:
            fixed = None
            if pat is not RANDOM:
                ph = start % len(pat)  # keep multi-byte patterns phase-aligned to file offset
                fixed = _tile(pat[ph:] + pat[:ph], BLOCK)
            off = start
            while off < end:
                n = min(BLOCK, end - off)
                buf = os.urandom(n) if pat is RANDOM else (fixed if n == BLOCK else fixed[:n])
                self._pwrite(fd, buf, off)
                h.update(buf)
                off += n
                written += n
                if self.progress:
                    self.progress.update(path, pass_no, n_passes, "write", written, total, n)
        os.fsync(fd)
        return h.digest()

    def _verify_pass(self, fd, size, expected, pass_no=1, n_passes=1, path=""):
        # Drop cached pages so the read-back hits the device, not RAM.
        # Best effort: some filesystems ignore the hint.
        if hasattr(os, "posix_fadvise"):
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        h = hashlib.blake2b(digest_size=16)
        extents = self._extents(fd, size)
        total = sum(e - s for s, e in extents)
        done = 0
        for start, end in extents:
            off = start
            while off < end:
                got = self._pread(fd, min(BLOCK, end - off), off)
                if not got:
                    raise ReadbackError(f"pass {pass_no}: short read at byte {off}")
                h.update(got)
                off += len(got)
                done += len(got)
                if self.progress:
                    self.progress.update(path, pass_no, n_passes, "verify", done, total, len(got))
        if h.digest() != expected:
            raise ReadbackError(f"pass {pass_no}: read-back mismatch ({path})")

    # ------------------------------------------------------------------
    def _remove(self, path, rec, rmdir=False):
        """Rename to random names (so the original name is not left in the
        directory entry), then unlink. Old names may persist in journals."""
        cur = path
        if self.scrub_names:
            try:
                cur = self._scrub_name(path)
                rec["renamed"] = cur != path
            except OSError as exc:
                self._warn(f"{path}: could not scrub file name: {exc}")
        try:
            (os.rmdir if rmdir else os.unlink)(cur)
        except OSError as exc:
            if cur != path:
                raise OSError(exc.errno, f"{exc.strerror} (renamed to {cur})") from exc
            raise

    def _scrub_name(self, path):
        d, base = os.path.split(path)
        cur = path
        length = min(max(len(os.fsencode(base)), 8), 200)
        for _ in range(NAME_ROUNDS):
            for _attempt in range(50):
                new = os.path.join(d, secrets.token_hex(length)[:length])
                if not os.path.lexists(new):
                    break
            else:
                break
            os.rename(cur, new)
            cur = new
            self._fsync_dir(d or ".")
        return cur

    @staticmethod
    def _fsync_dir(d):
        try:
            dfd = os.open(d, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)

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
                self._remove(dirpath, {}, rmdir=True)
                if self.verbose:
                    print(f"  {dirpath}: removed")
            except OSError as exc:
                failures += 1
                print(f"guttman: error: could not remove {dirpath}: {exc}", file=sys.stderr)
        return failures
