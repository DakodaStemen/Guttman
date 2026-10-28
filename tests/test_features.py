import io
import os
import subprocess
import sys

import pytest

from guttman import cli, detect
from guttman.patterns import RANDOM, _tile, dod_passes, gutmann_passes
from guttman.progress import Progress
from guttman.shredder import BLOCK, Shredder, VerifyError


def test_block_keeps_three_byte_patterns_in_phase():
    assert BLOCK % 3 == 0 and BLOCK % 2 == 0


def test_written_bytes_match_pattern(tmp_path):
    """Capture what hits the fd for a 3-byte pattern across a block boundary."""
    f = tmp_path / "x"
    f.write_bytes(b"z" * (BLOCK + 10))
    sh = Shredder()
    fd = os.open(f, os.O_RDWR)
    sh._write_pass(fd, BLOCK + 10, b"\x92\x49\x24")
    os.lseek(fd, 0, 0)
    data = os.read(fd, BLOCK + 10)
    os.close(fd)
    assert data == _tile(b"\x92\x49\x24", BLOCK + 10)


def test_verify_covers_random_passes(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"s" * 5000)
    calls = []
    sh = Shredder(verify=True)
    orig = sh._verify_pass
    sh._verify_pass = lambda *a, **k: (calls.append(1), orig(*a, **k))[1]
    sh.shred(str(f), dod_passes())
    assert len(calls) == 3  # zeros, ones, AND the random pass


def test_verify_detects_corruption(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"s" * 5000)
    sh = Shredder(verify=True)
    real_write = sh._write_pass

    def tampered(fd, size, pat, *a, **k):
        d = real_write(fd, size, pat, *a, **k)
        os.pwrite(fd, b"\xde\xad", 100)  # silent corruption after the pass
        os.fsync(fd)
        return d

    sh._write_pass = tampered
    with pytest.raises(VerifyError):
        sh.shred(str(f), dod_passes())
    assert f.exists()  # failed shred must not claim success by unlinking


def test_dry_run_changes_nothing(tmp_path, capsys):
    f = tmp_path / "keep.txt"
    f.write_bytes(b"precious")
    Shredder(dry_run=True, verify=True).shred(str(f), gutmann_passes())
    assert f.read_bytes() == b"precious"
    out = capsys.readouterr().out
    assert "dry-run" in out and "35 passes" in out


def test_dry_run_directory_keeps_tree(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a").write_bytes(b"a")
    assert Shredder(dry_run=True).shred_directory(str(tmp_path / "d"), dod_passes()) == 0
    assert (tmp_path / "d" / "a").read_bytes() == b"a"


def test_cli_dry_run_exit_zero(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"a")
    assert cli.main(["-n", "-q", str(f)]) == 0
    assert f.exists()


def test_cli_shreds_and_reports_missing(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"a")
    assert cli.main(["-q", "--verify", str(f)]) == 0
    assert not f.exists()
    assert cli.main(["-q", str(tmp_path / "nope")]) == 1


def test_cli_directory_needs_r(tmp_path):
    assert cli.main(["-q", str(tmp_path)]) == 1


def test_symlink_removed_target_untouched(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"do not touch")
    link = tmp_path / "link"
    link.symlink_to(target)
    Shredder().shred(str(link), dod_passes())
    assert not link.is_symlink()
    assert target.read_bytes() == b"do not touch"


def test_readonly_file_is_shredded(tmp_path):
    f = tmp_path / "ro"
    f.write_bytes(b"x" * 100)
    f.chmod(0o400)
    Shredder().shred(str(f), dod_passes())
    assert not f.exists()


def test_progress_output():
    buf = io.StringIO()
    p = Progress(stream=buf, interval=0)
    p.start_file("f")
    p.update("f", 1, 3, "write", 50, 100, 50)
    p.update("f", 1, 3, "write", 100, 100, 50)
    p.finish_file("f")
    out = buf.getvalue()
    assert "pass 1/3" in out and "100.0%" in out and "shredded" in out


def test_progress_wired_into_shredder(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"x" * 1000)
    buf = io.StringIO()
    Shredder(verify=True, progress=Progress(stream=buf, interval=0)).shred(str(f), dod_passes())
    assert "verify" in buf.getvalue() and "write" in buf.getvalue()


# --- detection ---

MOUNTINFO = (
    "25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,data=journal\n"
    "30 25 0:27 / /data rw - btrfs /dev/sdb1 rw,subvol=/\n"
    "31 25 0:28 / /pool rw - zfs tank/home rw\n"
    "32 25 0:29 / /srv rw - xfs /dev/sdc1 rw\n"
    "33 25 0:30 / /mnt/nas rw - nfs4 host:/x rw\n"
)


def test_parse_and_find_mount():
    ms = detect.parse_mountinfo(MOUNTINFO)
    assert detect.find_mount("/data/x/y", ms).fstype == "btrfs"
    assert detect.find_mount("/data2/x", ms).fstype == "ext4"  # not a prefix match of /data
    assert detect.find_mount("/pool", ms).fstype == "zfs"


@pytest.mark.parametrize("path,code", [
    ("/data/f", "cow"), ("/pool/f", "cow"), ("/f", "journal-data"),
    ("/srv/f", "journal"), ("/mnt/nas/f", "network"),
])
def test_fs_findings(path, code, tmp_path):
    codes = {f.code for f in detect.analyze_path("/", mountinfo=MOUNTINFO.replace("/ /", "/ /")) } if False else None
    ms = detect.parse_mountinfo(MOUNTINFO)
    m = detect.find_mount(path, ms)
    assert code in {f.code for f in detect.analyze_fs(m.fstype, m.options)}


def _fake_sysfs(root, rotational, discard, partition=True):
    disk = root / "devices" / "block" / "nvme0n1"
    (disk / "queue").mkdir(parents=True)
    (disk / "queue" / "rotational").write_text("1" if rotational else "0")
    (disk / "queue" / "discard_max_bytes").write_text("2199023255040" if discard else "0")
    part = disk / "nvme0n1p2"
    part.mkdir()
    (part / "partition").write_text("2")
    (root / "dev" / "block").mkdir(parents=True)
    (root / "dev" / "block" / "259:2").symlink_to(part)
    return root


def test_ssd_trim_detected(tmp_path):
    sysfs = _fake_sysfs(tmp_path, rotational=False, discard=True)
    t = detect.block_device_traits(os.makedev(259, 2), str(sysfs))
    assert t == {"rotational": False, "discard": True}


def test_hdd_detected(tmp_path):
    sysfs = _fake_sysfs(tmp_path, rotational=True, discard=False)
    t = detect.block_device_traits(os.makedev(259, 2), str(sysfs))
    assert t == {"rotational": True, "discard": False}


def test_device_mapper_slaves(tmp_path):
    sysfs = _fake_sysfs(tmp_path, rotational=False, discard=True)
    dm = tmp_path / "devices" / "virtual" / "dm-0"
    (dm / "slaves").mkdir(parents=True)
    (dm / "queue").mkdir()
    (dm / "queue" / "rotational").write_text("0")
    (dm / "slaves" / "nvme0n1p2").symlink_to(tmp_path / "devices" / "block" / "nvme0n1" / "nvme0n1p2")
    (sysfs / "dev" / "block" / "253:0").symlink_to(dm)
    t = detect.block_device_traits(os.makedev(253, 0), str(sysfs))
    assert t["rotational"] is False and t["discard"] is True


def test_unknown_device_is_not_claimed_safe(tmp_path):
    t = detect.block_device_traits(os.makedev(1, 1), str(tmp_path))
    assert t["rotational"] is None


def test_analyze_real_path_does_not_crash(tmp_path):
    assert isinstance(detect.analyze_path(str(tmp_path)), list)


def test_module_and_entry_point():
    r = subprocess.run([sys.executable, "-m", "guttman", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "guttman" in r.stdout
