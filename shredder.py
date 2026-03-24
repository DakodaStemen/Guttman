import os
import stat
import sys

from patterns import RANDOM, _tile

# 4 KB blocks — aligns to typical sector size and keeps memory usage flat
# on large files
BLOCK = 4096


class Shredder:
    def __init__(self, verbose=False, verify=False):
        self.verbose = verbose
        self.verify = verify

    def shred(self, path: str, passes: list) -> None:
        real = os.path.realpath(path)
        st = os.stat(real)
        size = st.st_size

        # chmod if needed — read-only files are common in archived directories
        if not os.access(real, os.W_OK):
            os.chmod(real, stat.S_IMODE(st.st_mode) | stat.S_IWRITE)

        if size == 0:
            if self.verbose:
                print(f"  {real}: empty, skipping passes")
            os.unlink(real)
            return

        try:
            fd = os.open(real, os.O_RDWR)
        except OSError as exc:
            print(f"guttman: cannot open {real}: {exc}", file=sys.stderr)
            raise

        try:
            for i, pat in enumerate(passes):
                if self.verbose:
                    label = "random" if pat is RANDOM else pat.hex()
                    print(f"  {real}: pass {i + 1}/{len(passes)} [{label}]")

                self._write_pass(fd, size, pat)

                if self.verify and pat is not RANDOM:
                    self._verify_pass(fd, size, pat)

            os.ftruncate(fd, 0)
            os.fsync(fd)
        finally:
            os.close(fd)

        os.unlink(real)
        if self.verbose:
            print(f"  {real}: deleted")

    def _write_pass(self, fd: int, size: int, pat) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        written = 0
        while written < size:
            n = min(BLOCK, size - written)
            buf = os.urandom(n) if pat is RANDOM else _tile(pat, n)
            os.write(fd, buf)
            written += n
        os.fsync(fd)

    def _verify_pass(self, fd: int, size: int, pat: bytes) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        offset = 0
        while offset < size:
            n = min(BLOCK, size - offset)
            got = os.read(fd, n)
            want = _tile(pat, len(got))
            if got != want:
                raise ValueError(
                    f"verify failed at byte {offset}: "
                    f"want {want[:8].hex()} got {got[:8].hex()}"
                )
            offset += len(got)

    def shred_directory(self, path: str, passes: list) -> None:
        for dirpath, _dirs, files in os.walk(path, topdown=False):
            for fname in files:
                fpath = os.path.join(dirpath, fname)
                try:
                    self.shred(fpath, passes)
                except Exception as exc:
                    print(f"warning: skipping {fpath}: {exc}", file=sys.stderr)
            try:
                os.rmdir(dirpath)
                if self.verbose:
                    print(f"  {dirpath}: removed")
            except OSError as exc:
                print(f"warning: could not remove {dirpath}: {exc}", file=sys.stderr)
