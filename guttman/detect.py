"""Storage-layer risk detection (Linux).

Overwriting a file only destroys the old bytes if the stack below honours
"write to the same place". These checks flag the common cases where it
doesn't. They are heuristics: a missing warning is NOT a guarantee.
"""
import os
from dataclasses import dataclass
from typing import List, Optional

COW_FS = {"btrfs", "zfs", "bcachefs", "nilfs2", "f2fs"}
JOURNAL_FS = {"ext3", "ext4", "xfs", "jfs", "reiserfs", "ntfs", "ntfs3"}
VOLATILE_OR_LAYERED = {"overlay", "overlayfs", "aufs", "tmpfs", "ramfs"}
NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "ceph", "glusterfs"}


@dataclass
class Finding:
    level: str   # "warn" | "info"
    code: str
    message: str


# Findings that mean "overwriting this file cannot be relied on" or "we cannot
# tell". The CLI refuses these unless --force-unsafe is given (fail closed).
BLOCKING_CODES = frozenset({"ssd", "cow", "unknown-fs", "device-unknown", "unsupported"})


def blocking(findings):
    """Findings that make the CLI refuse to proceed by default."""
    return [f for f in findings if f.code in BLOCKING_CODES]


@dataclass
class Mount:
    mountpoint: str
    fstype: str
    source: str
    options: str


def parse_mountinfo(text: str) -> List[Mount]:
    mounts = []
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        lf, rf = left.split(), right.split()
        if len(lf) < 6 or len(rf) < 2:
            continue
        mp = lf[4].replace("\\040", " ")
        opts = lf[5] + "," + (rf[2] if len(rf) > 2 else "")
        mounts.append(Mount(mp, rf[0], rf[1], opts))
    return mounts


def find_mount(path: str, mounts: List[Mount]) -> Optional[Mount]:
    path = os.path.realpath(path)
    best = None
    for m in mounts:
        mp = m.mountpoint.rstrip("/") or "/"
        if path == mp or path.startswith(mp.rstrip("/") + "/") or mp == "/":
            # later entries win ties (shadowing mounts are listed later)
            if best is None or len(mp) >= len(best.mountpoint):
                best = m
    return best


def _read(p):
    try:
        with open(p) as fh:
            return fh.read().strip()
    except OSError:
        return None


def block_device_traits(devnum: int, sysfs: str = "/sys", depth: int = 0) -> dict:
    """Return {'rotational': bool|None, 'discard': bool|None} for a st_dev.

    Walks partition -> whole disk and device-mapper -> slaves.
    """
    major, minor = os.major(devnum), os.minor(devnum)
    return _traits_from_sysfs(os.path.join(sysfs, "dev", "block", f"{major}:{minor}"), depth)


def _traits_from_sysfs(node: str, depth: int = 0) -> dict:
    out = {"rotational": None, "discard": None}
    if depth > 4 or not os.path.exists(node):
        return out
    node = os.path.realpath(node)
    if os.path.exists(os.path.join(node, "partition")):
        node = os.path.dirname(node)
    slaves = os.path.join(node, "slaves")
    rot = _read(os.path.join(node, "queue", "rotational"))
    dmax = _read(os.path.join(node, "queue", "discard_max_bytes"))
    has_slaves = os.path.isdir(slaves) and bool(os.listdir(slaves))
    if rot is not None and not has_slaves:
        out["rotational"] = rot == "1"
        out["discard"] = (dmax not in (None, "0")) if dmax is not None else None
        return out
    if has_slaves:
        subs = [_traits_from_sysfs(os.path.join(slaves, s), depth + 1) for s in sorted(os.listdir(slaves))]
        rots = [s["rotational"] for s in subs if s["rotational"] is not None]
        dis = [s["discard"] for s in subs if s["discard"] is not None]
        if rots:
            out["rotational"] = all(rots)  # any flash member => treat as non-rotational
        if dis:
            out["discard"] = any(dis)
    return out


def analyze_fs(fstype: str, options: str) -> List[Finding]:
    f = []
    opts = set(options.split(","))
    if fstype in COW_FS:
        f.append(Finding("warn", "cow",
            f"{fstype} is copy-on-write/log-structured: overwrites go to NEW blocks and the old "
            "data stays on disk (snapshots may also hold it)."))
    if fstype in ("ext3", "ext4") and "data=journal" in opts:
        f.append(Finding("warn", "journal-data",
            "mounted with data=journal: file DATA is also written to the journal, "
            "leaving copies outside the file."))
    elif fstype in JOURNAL_FS:
        f.append(Finding("info", "journal",
            f"{fstype} journals metadata (file names, sizes, timestamps); "
            "these are not overwritten by shredding."))
    if fstype in VOLATILE_OR_LAYERED:
        f.append(Finding("warn", "layered",
            f"{fstype}: writes may land in a different layer/RAM than the file you named."))
    if fstype in NETWORK_FS or fstype.startswith("fuse"):
        f.append(Finding("warn", "network",
            f"{fstype}: the remote server/backing store decides what happens to old bytes."))
    return f


def analyze_path(path: str, mountinfo: Optional[str] = None, sysfs: str = "/sys") -> List[Finding]:
    """Findings for the storage that holds `path` (an existing file or dir)."""
    findings: List[Finding] = []
    if not os.path.exists("/proc/self/mountinfo") and mountinfo is None:
        return [Finding("info", "unsupported", "storage detection is Linux-only; no checks run")]
    text = mountinfo if mountinfo is not None else _read("/proc/self/mountinfo") or ""
    target = os.path.dirname(os.path.abspath(path)) if os.path.islink(path) else path
    m = find_mount(target, parse_mountinfo(text))
    if m is None:
        return [Finding("info", "unknown-fs", "could not determine filesystem")]
    findings += analyze_fs(m.fstype, m.options)
    try:
        traits = block_device_traits(os.stat(target).st_dev, sysfs)
    except OSError:
        traits = {"rotational": None, "discard": None}
    if traits["rotational"] is False:
        msg = ("backing device is flash (SSD/NVMe): wear-levelling remaps writes, so old cells "
               "can survive an overwrite.")
        if traits["discard"]:
            msg += " TRIM/discard is supported - run `fstrim` after deleting, but TRIM is not a secure erase."
        findings.append(Finding("warn", "ssd", msg))
    elif traits["rotational"] is None and m.fstype not in VOLATILE_OR_LAYERED:
        findings.append(Finding("info", "device-unknown",
            "could not identify the backing block device (SSD/TRIM status unknown)."))
    return findings
