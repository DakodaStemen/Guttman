"""`guttman advise` - print (never run) the right whole-device sanitization commands.

Everything here only READS /proc, /sys and stat(). The commands in the output
are text for a human to review and run. Most of them destroy a whole device.

SP 800-88 mapping used (NIST SP 800-88 Rev. 2, Guidelines for Media
Sanitization): Clear = logical techniques (e.g. overwrite via normal I/O);
Purge = techniques that make recovery infeasible even with state-of-the-art lab
techniques (e.g. firmware sanitize / secure-erase commands, cryptographic
erase); Destroy = physical destruction. Check the publication for the
normative wording; this tool's mapping is a summary, not a compliance claim.
"""
import os
import re
import stat
import sys
from dataclasses import dataclass, field

from guttman.detect import find_mount, parse_mountinfo, _read

WARNING = (
    "These commands DESTROY ALL DATA on the whole device. guttman does not run\n"
    "them. Check the device name twice, unmount it, and prefer booting from\n"
    "other media for the system disk."
)


@dataclass
class DeviceInfo:
    target: str
    fstype: str | None = None
    devnode: str | None = None        # e.g. /dev/nvme0n1p2 (what holds the target)
    disk: str | None = None           # whole disk name, e.g. nvme0n1
    kind: str = "unknown"                # nvme | sata-or-scsi | mmc | virtual | unknown
    rotational: bool | None = None
    luks: bool = False
    dm_name: str | None = None
    underlying: list[str] = field(default_factory=list)   # whole disks under a dm stack
    notes: list[str] = field(default_factory=list)


def _kind(disk: str) -> str:
    if disk.startswith("nvme"):
        return "nvme"
    if disk.startswith("mmcblk"):
        return "mmc"
    if re.match(r"^(sd|hd|vd|xvd)[a-z]+$", disk):
        return "sata-or-scsi" if not disk.startswith(("vd", "xvd")) else "virtual"
    if disk.startswith(("loop", "ram", "zram")):
        return "virtual"
    return "unknown"


def _node_for_devnum(devnum: int, sysfs: str) -> str | None:
    p = os.path.join(sysfs, "dev", "block", f"{os.major(devnum)}:{os.minor(devnum)}")
    return os.path.realpath(p) if os.path.exists(p) else None


def _whole_disk_node(node: str) -> str:
    node = os.path.realpath(node)   # /sys/.../slaves/* entries are symlinks
    return os.path.dirname(node) if os.path.exists(os.path.join(node, "partition")) else node


def inspect_devnum(devnum: int, info: DeviceInfo, sysfs: str = "/sys", depth: int = 0) -> None:
    node = _node_for_devnum(devnum, sysfs)
    if node is None or depth > 5:
        return
    _inspect_node(node, info, sysfs, depth)


def _inspect_node(node: str, info: DeviceInfo, sysfs: str, depth: int) -> None:
    node = _whole_disk_node(node)
    name = os.path.basename(node)
    uuid = _read(os.path.join(node, "dm", "uuid")) or ""
    slaves_dir = os.path.join(node, "slaves")
    slaves = sorted(os.listdir(slaves_dir)) if os.path.isdir(slaves_dir) else []
    if uuid.upper().startswith("CRYPT-LUKS"):
        info.luks = True
        info.dm_name = _read(os.path.join(node, "dm", "name")) or name
    if slaves:
        for s in slaves:
            _inspect_node(os.path.join(slaves_dir, s), info, sysfs, depth + 1)
        return
    if info.disk is None:
        info.disk = name
        info.kind = _kind(name)
        rot = _read(os.path.join(node, "queue", "rotational"))
        info.rotational = None if rot is None else rot == "1"
    if name not in info.underlying:
        info.underlying.append(name)


def inspect_target(target: str, mountinfo: str | None = None, sysfs: str = "/sys") -> DeviceInfo:
    info = DeviceInfo(target=target)
    st = os.stat(target)
    if stat.S_ISBLK(st.st_mode):
        info.devnode = target
        inspect_devnum(st.st_rdev, info, sysfs)
        return info
    text = mountinfo if mountinfo is not None else (_read("/proc/self/mountinfo") or "")
    m = find_mount(target, parse_mountinfo(text))
    if m is not None:
        info.fstype = m.fstype
        if m.source.startswith("/dev/"):
            info.devnode = m.source
    inspect_devnum(st.st_dev, info, sysfs)
    if info.disk is None:
        info.notes.append("could not map the path to a block device (virtual, network or "
                          "btrfs/ZFS multi-device filesystem?)")
    return info


# ----------------------------------------------------------------------
def _classification(info: DeviceInfo) -> list[str]:
    out = []
    if info.fstype in {"btrfs", "zfs", "bcachefs", "f2fs", "nilfs2"}:
        out.append(f"filesystem {info.fstype} is copy-on-write/log-structured: per-file overwrite does not work.")
    if info.rotational is False:
        out.append("flash storage (non-rotational): per-file overwrite does not work "
                   "(wear-levelling; Wei et al., FAST'11).")
    elif info.rotational is True:
        out.append("rotational disk: overwrite is a valid SP 800-88 'Clear' technique for "
                   "the file contents; metadata, journals and snapshots are still outside it.")
    else:
        out.append("storage type unknown: treat as not overwritable.")
    if info.luks:
        out.append(f"LUKS volume ({info.dm_name}): cryptographic erase (destroying all key "
                   "slots) is available.")
    return out


def advise(info: DeviceInfo) -> str:
    dev = f"/dev/{info.disk}" if info.disk else "/dev/DEVICE"
    L = []
    add = L.append
    add(f"guttman advise: {info.target}")
    add("=" * 60)
    add(f"filesystem : {info.fstype or 'n/a'}")
    add(f"device     : {info.devnode or 'unknown'}"
        + (f"  (whole disk: {dev}; type: {info.kind})" if info.disk else ""))
    if len(info.underlying) > 1:
        add("underlying : " + ", ".join(f"/dev/{d}" for d in info.underlying))
    for n in info.notes:
        add(f"note       : {n}")
    add("")
    add("Assessment")
    for c in _classification(info):
        add(f"  - {c}")
    add("")
    add("NIST SP 800-88 Rev. 2 mapping (summary; read the publication for normative text)")
    add("  Clear   : logical overwrite via normal I/O. guttman does this for files on")
    add("            rotational, non-CoW storage. Not reliable on flash/CoW.")
    add("  Purge   : device-level sanitize / secure erase / cryptographic erase (below).")
    add("  Destroy : physical destruction. Use when Purge is unavailable or unverifiable.")
    add("")
    add(WARNING)
    add("")

    k = info.kind
    if k == "nvme" or any(u.startswith("nvme") for u in info.underlying):
        ctrl = re.sub(r"n\d+$", "", info.disk or "nvme0") if info.disk else "nvme0"
        add(f"NVMe ({dev}) - Purge:")
        add(f"  nvme id-ctrl /dev/{ctrl} -H | grep -i sanicap     # which sanitize actions exist")
        add(f"  nvme sanitize /dev/{ctrl} --sanact=4              # crypto erase (if supported)")
        add(f"  nvme sanitize /dev/{ctrl} --sanact=2              # block erase (if supported)")
        add(f"  nvme sanitize-log /dev/{ctrl}                     # poll until finished")
        add("  # alternative if sanitize is unsupported (weaker guarantee):")
        add(f"  nvme format {dev} --ses=2                         # crypto-erase format (--ses=1 = user-data erase)")
        add("")
    if k in ("sata-or-scsi",) or any(re.match(r"^(sd|hd)[a-z]+$", u) for u in info.underlying):
        add(f"ATA/SATA ({dev}) - Purge (the device must not be 'frozen'; USB bridges often block this):")
        add(f"  hdparm -I {dev} | grep -iE 'frozen|not.*enabled|supported:.*erase'")
        add(f"  hdparm --user-master u --security-set-pass PASS {dev}")
        add(f"  hdparm --user-master u --security-erase PASS {dev}            # or --security-erase-enhanced")
        add("  # SAS/SCSI disks: use `sg_sanitize` (sg3_utils) instead.")
        add("")
    if info.kind in ("sata-or-scsi", "nvme", "mmc", "virtual") or info.disk:
        add(f"Any block device with discard support ({dev}):")
        add(f"  blkdiscard -s {dev}                  # secure discard; fails if unsupported - do NOT fall back to plain discard")
        add("  # Plain `blkdiscard` / fstrim are NOT secure erase; they only tell the drive space is free.")
        add("")
    if info.luks:
        add("Cryptographic erase - Purge ONLY if the data was always encrypted with a strong key and")
        add("no other copy of the key or LUKS header exists (backups, escrow, initramfs):")
        add("  cryptsetup luksDump /dev/LUKS_PARTITION          # the partition under the mapping, not /dev/mapper/*")
        add("  cryptsetup luksErase /dev/LUKS_PARTITION         # irreversibly wipes ALL key slots")
    else:
        add("Cryptographic erase (cryptsetup luksErase) applies only to LUKS volumes; none was")
        add("detected under this target. If you use LUKS elsewhere: encrypt first, destroy the key later.")
    add("")
    if info.rotational is True and info.fstype not in {"btrfs", "zfs", "bcachefs", "f2fs", "nilfs2"}:
        add("Rotational disk, single file: `guttman -m dod FILE` is a Clear-level technique.")
        add("Whole rotational disk: ATA Secure Erase above, or a single full-device overwrite pass.")
    else:
        add("Single file on this storage: no reliable per-file option. Migrate what you keep, then")
        add("sanitize the whole device (above) - or destroy the key if the volume is encrypted.")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="guttman advise",
        description="Print (never execute) the whole-device sanitization commands appropriate "
                    "for a path or block device, with an SP 800-88 clear/purge mapping.")
    p.add_argument("target", metavar="PATH|DEVICE")
    args = p.parse_args(argv)
    try:
        info = inspect_target(args.target)
    except OSError as exc:
        print(f"guttman advise: {args.target}: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(advise(info))
    return 0
