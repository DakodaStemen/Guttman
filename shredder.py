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
        """Securely shred a regular file by overwriting with passes then unlinking.

        Refuses symlinks, multiply-linked files, and non-regular files.
        Anchors the parent directory with dir_fd where supported.
        Residual race disclosure: dir_fd anchors the directory but identity
        verification and unlink are not atomic; exclusive control of the target
        directory is required for safety against hostile concurrent modification.
        O_NOFOLLOW covers only the final path component.
        """
        if os.path.islink(path):
            raise ValueError(f"{path}: symlinks are not supported")

        parent_dir = os.path.dirname(path) or "."
        base_name = os.path.basename(path)

        parent_fd = None
        use_dir_fd = (
            hasattr(os, "supports_dir_fd")
            and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd
            and os.unlink in os.supports_dir_fd
        )
        if use_dir_fd:
            try:
                parent_fd = os.open(parent_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            except OSError:
                parent_fd = None

        open_target = base_name if parent_fd is not None else path
        open_kwargs = {"dir_fd": parent_fd} if parent_fd is not None else {}

        try:
            fd = None
            try:
                open_flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                try:
                    fd = os.open(open_target, open_flags, **open_kwargs)
                except PermissionError:
                    # File may be read-only: open read-only with O_NOFOLLOW to verify and fchmod descriptor
                    ro_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                    ro_fd = os.open(open_target, ro_flags, **open_kwargs)
                    try:
                        ro_st = os.fstat(ro_fd)
                        if not stat.S_ISREG(ro_st.st_mode):
                            raise ValueError(f"{path}: not a regular file")
                        if ro_st.st_nlink > 1:
                            raise ValueError(
                                f"{path}: multiply-linked files are not supported ({ro_st.st_nlink} links)"
                            )
                        os.fchmod(ro_fd, stat.S_IMODE(ro_st.st_mode) | stat.S_IWUSR)
                        try:
                            fd = os.open(f"/proc/self/fd/{ro_fd}", open_flags)
                        except (OSError, FileNotFoundError):
                            fd = os.open(open_target, open_flags, **open_kwargs)
                    finally:
                        os.close(ro_fd)

                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(f"{path}: not a regular file")
                if st.st_nlink > 1:
                    raise ValueError(f"{path}: multiply-linked files are not supported ({st.st_nlink} links)")

                size = st.st_size
                orig_dev = st.st_dev
                orig_ino = st.st_ino

                if size > 0:
                    for i, pat in enumerate(passes):
                        if self.verbose:
                            label = "random" if pat is RANDOM else pat.hex()
                            print(f"  {path}: pass {i + 1}/{len(passes)} [{label}]")

                        self._write_pass(fd, size, pat)

                        # Random passes are not verified because os.urandom output is not retained/buffered
                        if self.verify and pat is not RANDOM:
                            self._verify_pass(fd, size, pat)

                    os.ftruncate(fd, 0)
                    os.fsync(fd)
                else:
                    if self.verbose:
                        print(f"  {path}: empty, skipping passes")
            finally:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

            # Verify directory entry still points to the same inode before unlinking
            cur_st = os.stat(open_target, follow_symlinks=False, **open_kwargs)
            if cur_st.st_dev != orig_dev or cur_st.st_ino != orig_ino:
                raise RuntimeError(f"refusing to unlink {path}: entry changed while opened")

            os.unlink(open_target, **open_kwargs)
            if self.verbose:
                print(f"  {path}: deleted")
        finally:
            if parent_fd is not None:
                try:
                    os.close(parent_fd)
                except OSError:
                    pass

    def _write_pass(self, fd: int, size: int, pat) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        written = 0
        while written < size:
            n = min(BLOCK, size - written)
            buf = os.urandom(n) if pat is RANDOM else _tile(pat, n)
            buf_written = 0
            while buf_written < n:
                res = os.write(fd, buf[buf_written:])
                if res <= 0:
                    raise OSError("write failed: zero bytes written")
                buf_written += res
            written += n
        os.fsync(fd)

    def _verify_pass(self, fd: int, size: int, pat) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        offset = 0
        while offset < size:
            n = min(BLOCK, size - offset)
            got = os.read(fd, n)
            if len(got) != n:
                raise ValueError(
                    f"verify failed at byte {offset}: "
                    f"expected {n} bytes, got {len(got)}"
                )
            want = _tile(pat, n)
            if got != want:
                raise ValueError(
                    f"verify failed at byte {offset}: "
                    f"want {want[:8].hex()} got {got[:8].hex()}"
                )
            offset += n

    def shred_directory(self, path: str, passes: list) -> int:
        """Recursively shred all regular files under path and remove directories.

        Symlinks are never followed and never unlinked.
        Returns the count of encountered failures.
        """
        if os.path.islink(path):
            print(f"warning: skipping symlink {path}", file=sys.stderr)
            return 1

        errors = 0
        for dirpath, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for fname in files:
                fpath = os.path.join(dirpath, fname)
                if os.path.islink(fpath):
                    print(f"warning: skipping symlink {fpath}", file=sys.stderr)
                    errors += 1
                    continue
                try:
                    self.shred(fpath, passes)
                except Exception as exc:
                    print(f"warning: skipping {fpath}: {exc}", file=sys.stderr)
                    errors += 1

            for dname in dirs:
                dpath = os.path.join(dirpath, dname)
                if os.path.islink(dpath):
                    print(f"warning: skipping symlink {dpath}", file=sys.stderr)
                    errors += 1

            try:
                os.rmdir(dirpath)
                if self.verbose:
                    print(f"  {dirpath}: removed")
            except OSError as exc:
                print(f"warning: could not remove {dirpath}: {exc}", file=sys.stderr)
                errors += 1

        return errors
