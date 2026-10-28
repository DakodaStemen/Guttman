"""Single-line terminal progress display (stderr)."""
import sys
import time

_BAR = 24


def fmt_rate(bps: float) -> str:
    for unit in ("B/s", "KiB/s", "MiB/s", "GiB/s"):
        if bps < 1024 or unit == "GiB/s":
            return f"{bps:.0f} {unit}" if unit == "B/s" else f"{bps:.1f} {unit}"
        bps /= 1024
    return ""


def fmt_size(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


class Progress:
    """Callable progress sink used by Shredder.

    update(path, pass_no, n_passes, phase, done, total) is called after each
    block. Redraws are throttled so the display costs next to nothing.
    """

    def __init__(self, stream=None, interval=0.05):
        self.stream = stream or sys.stderr
        self.interval = interval
        self._last = 0.0
        self._t0 = None
        self._bytes = 0
        self._dirty = False

    def start_file(self, path):
        self._t0 = time.monotonic()
        self._bytes = 0

    def update(self, path, pass_no, n_passes, phase, done, total, delta=0):
        self._bytes += delta
        now = time.monotonic()
        if done < total and now - self._last < self.interval:
            return
        self._last = now
        frac = done / total if total else 1.0
        fill = int(_BAR * frac)
        bar = "#" * fill + "-" * (_BAR - fill)
        elapsed = max(now - (self._t0 or now), 1e-9)
        rate = fmt_rate(self._bytes / elapsed)
        name = path if len(path) <= 28 else "..." + path[-25:]
        self.stream.write(
            f"\r\x1b[2K{name}  pass {pass_no}/{n_passes} {phase:<6} "
            f"[{bar}] {frac * 100:5.1f}%  {rate}"
        )
        self.stream.flush()
        self._dirty = True

    def finish_file(self, path, ok=True):
        if self._dirty:
            elapsed = time.monotonic() - (self._t0 or time.monotonic())
            self.stream.write(
                f"\r\x1b[2K{path}: {'shredded' if ok else 'FAILED'} "
                f"({fmt_size(self._bytes)} I/O in {elapsed:.2f}s)\n"
            )
            self.stream.flush()
            self._dirty = False
