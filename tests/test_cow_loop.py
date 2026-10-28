"""Demonstrates, on a real loop-mounted filesystem, that overwriting works on an
in-place filesystem (ext4) and does NOT on a copy-on-write one (btrfs).

Needs root or passwordless sudo, losetup, mount and the mkfs tool for the
filesystem. Otherwise the tests SKIP with the reason. They never touch real
devices: everything lives in a sparse image file under pytest's tmp_path.
"""
import os
import shutil
import subprocess

import pytest

from guttman import cli
from guttman.patterns import dod_passes
from guttman.shredder import Shredder

MARKER_LEN = 256 * 1024


def _sudo():
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo") and subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
        return ["sudo", "-n"]
    return None


def _which(tool):
    return shutil.which(tool) or next(
        (p for p in (f"/usr/sbin/{tool}", f"/sbin/{tool}") if os.path.exists(p)), None)


def _need(fs):
    sudo = _sudo()
    if sudo is None:
        pytest.skip("loop-mount tests need root or passwordless sudo")
    for tool in ("losetup", "mount", "umount", f"mkfs.{fs}"):
        if _which(tool) is None:
            pytest.skip(f"{tool} not installed")
    return sudo


def _run(sudo, *cmd):
    return subprocess.run([*sudo, *cmd], check=True, capture_output=True, text=True)


@pytest.fixture
def loopfs(tmp_path):
    made = {}

    def make(fs, size_mib=300):
        sudo = _need(fs)
        img = tmp_path / f"{fs}.img"
        with open(img, "wb") as fh:
            fh.truncate(size_mib * 2**20)
        try:
            loop = _run(sudo, "losetup", "--find", "--show", str(img)).stdout.strip()
        except subprocess.CalledProcessError as exc:
            pytest.skip(f"cannot create loop device here: {exc.stderr.strip()}")
        made["loop"], made["sudo"] = loop, sudo
        try:
            _run(sudo, _which(f"mkfs.{fs}"), "-q", *(["-f"] if fs == "btrfs" else []), loop)
            mnt = tmp_path / "mnt"
            mnt.mkdir()
            _run(sudo, "mount", loop, str(mnt))
        except subprocess.CalledProcessError as exc:
            pytest.skip(f"cannot create/mount {fs} on a loop device here: {exc.stderr.strip()}")
        made["mnt"] = mnt
        _run(sudo, "chown", f"{os.getuid()}:{os.getgid()}", str(mnt))
        return mnt, img

    yield make
    if "mnt" in made:
        subprocess.run([*made["sudo"], "umount", str(made["mnt"])], capture_output=True)
    if "loop" in made:
        subprocess.run([*made["sudo"], "losetup", "-d", made["loop"]], capture_output=True)


def _marker_survives(img, mnt, marker, sudo):
    """Unmount (flushes everything), then look for a 4 KiB slice of the marker in the raw image."""
    needle = marker[MARKER_LEN // 2: MARKER_LEN // 2 + 4096]
    subprocess.run([*sudo, "umount", str(mnt)], check=True, capture_output=True)
    with open(img, "rb") as fh:
        return needle in fh.read()


def _shred_marker(mnt):
    marker = os.urandom(MARKER_LEN)         # incompressible, unique
    f = mnt / "secret.bin"
    f.write_bytes(marker)
    os.sync()
    Shredder(verify=True).shred(str(f), dod_passes())   # engine directly: policy is tested separately
    os.sync()
    return marker


def test_control_ext4_overwrite_destroys_old_bytes(loopfs):
    mnt, img = loopfs("ext4")
    marker = _shred_marker(mnt)
    assert not _marker_survives(img, mnt, marker, _sudo())


def test_btrfs_copy_on_write_keeps_old_bytes_after_shred(loopfs):
    """The limitation guttman refuses by default: on btrfs the old extent is
    freed, not overwritten, so the 'shredded' data is still in the image."""
    mnt, img = loopfs("btrfs")
    marker = _shred_marker(mnt)
    assert _marker_survives(img, mnt, marker, _sudo()), (
        "expected the pre-shred data to remain on btrfs (copy-on-write); "
        "if this fails the test setup no longer demonstrates the limitation")


def test_cli_refuses_btrfs_mount_by_default(loopfs):
    mnt, img = loopfs("btrfs")
    f = mnt / "secret.bin"
    f.write_bytes(b"s" * 4096)
    assert cli.main(["-q", str(f)]) == cli.EXIT_REFUSED
    assert f.exists()
