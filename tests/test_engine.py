"""Filename scrubbing, sparse files, I/O modes."""
import os

import pytest

from guttman.patterns import dod_passes
from guttman.shredder import Shredder


def test_name_scrub_renames_before_unlink(tmp_path, monkeypatch):
    f = tmp_path / "very-secret-name.txt"
    f.write_bytes(b"x" * 100)
    seen = []
    real = os.rename
    monkeypatch.setattr(os, "rename", lambda a, b: (seen.append((a, b)), real(a, b))[1])
    Shredder().shred(str(f), dod_passes())
    assert len(seen) == 3
    assert seen[0][0] == str(f)
    assert all("very-secret-name" not in b for _, b in seen)
    assert os.listdir(tmp_path) == []


def test_name_scrub_disabled(tmp_path, monkeypatch):
    f = tmp_path / "n"
    f.write_bytes(b"x")
    monkeypatch.setattr(os, "rename", lambda *a: pytest.fail("renamed"))
    Shredder(scrub_names=False).shred(str(f), dod_passes())
    assert not f.exists()


def test_directory_names_scrubbed(tmp_path):
    d = tmp_path / "secretdir"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "a").write_bytes(b"a")
    assert Shredder().shred_directory(str(d), dod_passes()) == 0
    assert os.listdir(tmp_path) == []


def _make_sparse(path, size=8 * 2**20):
    with open(path, "wb") as fh:
        fh.truncate(size)
        fh.seek(2**20)
        fh.write(b"A" * 8192)
        fh.seek(size - 4096)
        fh.write(b"B" * 4096)


def test_sparse_file_holes_not_allocated(tmp_path):
    f = tmp_path / "sparse"
    _make_sparse(f)
    st = os.stat(f)
    if st.st_blocks * 512 >= st.st_size:
        pytest.skip("filesystem does not support sparse files")
    sh = Shredder(verify=True)
    fd = os.open(f, os.O_RDWR)
    ext = sh._extents(fd, st.st_size)
    os.close(fd)
    data = sum(e - s for s, e in ext)
    assert 0 < data < st.st_size // 4
    sh.shred(str(f), dod_passes())
    rec = sh.records[0]
    assert rec["sparse"] is True and rec["data_bytes"] == data and rec["readback_checked"]
    assert rec["bytes_written"] == data * 3
    assert not f.exists()


def test_sparse_overwrite_keeps_file_sparse_and_overwrites_data(tmp_path):
    f = tmp_path / "sparse"
    _make_sparse(f)
    st = os.stat(f)
    if st.st_blocks * 512 >= st.st_size:
        pytest.skip("filesystem does not support sparse files")
    sh = Shredder(scrub_names=False)
    fd = os.open(f, os.O_RDWR)
    sh._write_pass(fd, st.st_size, b"\x00")
    os.close(fd)
    after = os.stat(f)
    assert after.st_blocks <= st.st_blocks + 16     # no hole filling
    raw = f.read_bytes()
    assert b"A" not in raw and b"B" not in raw


def test_multibyte_pattern_phase_across_extents(tmp_path):
    f = tmp_path / "p"
    _make_sparse(f)
    st = os.stat(f)
    sh = Shredder()
    fd = os.open(f, os.O_RDWR)
    sh._write_pass(fd, st.st_size, b"\x92\x49\x24")
    os.lseek(fd, 0, 0)
    os.close(fd)
    raw = f.read_bytes()
    pat = b"\x92\x49\x24"
    for off in (2**20, 2**20 + 1, st.st_size - 4096, st.st_size - 3):
        assert raw[off] == pat[off % 3], off


@pytest.mark.parametrize("mode", ["buffered", "sync", "direct"])
def test_io_modes(tmp_path, mode):
    f = tmp_path / "io"
    f.write_bytes(os.urandom(3 * 2**20 + 123))     # aligned blocks + unaligned tail
    sh = Shredder(verify=True, io_mode=mode)
    sh.shred(str(f), dod_passes())
    assert not f.exists() and sh.records[0]["readback_checked"]
    io = sh.records[0]["io"]
    assert io.startswith("buffered" if mode == "buffered" else "O_")


def test_direct_io_contents_correct(tmp_path):
    f = tmp_path / "d"
    f.write_bytes(os.urandom(2 * 2**20 + 77))
    sh = Shredder(io_mode="direct", scrub_names=False)
    rec = {}
    fd = sh._open(str(f), rec)
    try:
        sh._write_pass(fd, f.stat().st_size, b"\xff")
    finally:
        os.close(fd)
        if sh._dfd is not None:
            os.close(sh._dfd)
    assert f.read_bytes() == b"\xff" * (2 * 2**20 + 77)


def test_unknown_io_mode_rejected():
    with pytest.raises(ValueError):
        Shredder(io_mode="bogus")


def test_symlink_name_scrubbed_target_untouched(tmp_path):
    t = tmp_path / "t"
    t.write_bytes(b"keep")
    (tmp_path / "l").symlink_to(t)
    Shredder().shred(str(tmp_path / "l"), dod_passes())
    assert os.listdir(tmp_path) == ["t"] and t.read_bytes() == b"keep"
