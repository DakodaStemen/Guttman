import os

from guttman import advise, cli


def _sysfs(root, disk="nvme0n1", rot="0", luks=False):
    d = root / "devices" / "block" / disk
    (d / "queue").mkdir(parents=True)
    (d / "queue" / "rotational").write_text(rot)
    part = d / f"{disk}p3"
    part.mkdir()
    (part / "partition").write_text("3")
    (root / "dev" / "block").mkdir(parents=True)
    (root / "dev" / "block" / "259:3").symlink_to(part)
    dm = root / "devices" / "virtual" / "dm-0"
    (dm / "slaves").mkdir(parents=True)
    (dm / "dm").mkdir()
    (dm / "dm" / "uuid").write_text("CRYPT-LUKS2-abc-cryptroot" if luks else "LVM-xyz")
    (dm / "dm" / "name").write_text("cryptroot")
    (dm / "slaves" / f"{disk}p3").symlink_to(part)
    (root / "dev" / "block" / "253:0").symlink_to(dm)
    return str(root)


def test_dm_over_partition_resolves_to_whole_disk(tmp_path):
    sysfs = _sysfs(tmp_path, luks=True)
    info = advise.DeviceInfo(target="x")
    advise.inspect_devnum(os.makedev(253, 0), info, sysfs)
    assert info.disk == "nvme0n1" and info.kind == "nvme" and info.luks
    assert info.rotational is False


def test_nvme_luks_advice_contains_expected_commands(tmp_path):
    sysfs = _sysfs(tmp_path, luks=True)
    info = advise.DeviceInfo(target="x", fstype="ext4", devnode="/dev/mapper/cryptroot")
    advise.inspect_devnum(os.makedev(253, 0), info, sysfs)
    out = advise.advise(info)
    assert "nvme sanitize /dev/nvme0 --sanact=4" in out
    assert "blkdiscard -s /dev/nvme0n1" in out
    assert "cryptsetup luksErase" in out
    assert "Clear" in out and "Purge" in out and "800-88 Rev. 2" in out
    assert "hdparm --user-master u --security-erase" not in out


def test_sata_advice_has_hdparm_and_no_luks_erase(tmp_path):
    sysfs = _sysfs(tmp_path, disk="sda", rot="1")
    info = advise.DeviceInfo(target="x", fstype="ext4")
    advise.inspect_devnum(os.makedev(253, 0), info, sysfs)
    out = advise.advise(info)
    assert "hdparm --user-master u --security-erase" in out
    assert "nvme sanitize" not in out
    assert "  cryptsetup luksErase" not in out
    assert "rotational disk" in out


def test_cow_fs_warns_even_on_rotational(tmp_path):
    info = advise.DeviceInfo(target="x", fstype="btrfs", disk="sda", kind="sata-or-scsi", rotational=True)
    assert "copy-on-write" in advise.advise(info)


def test_advise_never_executes(tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("exec")))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("exec")))
    monkeypatch.setattr(os, "system", lambda *a: (_ for _ in ()).throw(AssertionError("exec")))
    assert cli.main(["advise", str(tmp_path)]) == 0


def test_advise_subcommand_output_and_missing(tmp_path, capsys):
    assert cli.main(["advise", str(tmp_path)]) == 0
    assert "guttman advise" in capsys.readouterr().out
    assert cli.main(["advise", str(tmp_path / "nope")]) == 1
