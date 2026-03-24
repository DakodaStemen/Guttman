import os

# sentinel value — means "generate os.urandom for this pass, don't tile a fixed pattern"
RANDOM = "random"


def _tile(pattern: bytes, size: int) -> bytes:
    if not pattern:
        return b""
    q, r = divmod(size, len(pattern))
    return pattern * q + pattern[:r]


def dod_passes() -> list:
    # DoD 5220.22-M: zeros, ones, then random. Simple, fast, good enough for most cases.
    return [b"\x00", b"\xff", RANDOM]


def gutmann_passes() -> list:
    # Peter Gutmann's 35-pass method from his 1996 paper.
    # The fixed patterns (passes 5-31) were designed to target residual magnetic
    # encoding on MFM and RLL drives. On modern drives they're mostly cargo cult,
    # but the method is still requested by compliance teams and paranoid users alike.
    # Structure: 4 random, 27 fixed, 4 random.
    fixed = [
        b"\x55", b"\xaa",
        b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
        b"\x00", b"\x11", b"\x22", b"\x33", b"\x44",
        b"\x55", b"\x66", b"\x77", b"\x88", b"\x99",
        b"\xaa", b"\xbb", b"\xcc", b"\xdd", b"\xee", b"\xff",
        b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
        b"\x6d\xb6\xdb", b"\xb6\xdb\x6d", b"\xdb\x6d\xb6",
    ]
    return [RANDOM] * 4 + fixed + [RANDOM] * 4


def random_passes(n: int) -> list:
    return [RANDOM] * n
