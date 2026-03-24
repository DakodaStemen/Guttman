import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from patterns import RANDOM, _tile, dod_passes, gutmann_passes, random_passes
from shredder import Shredder


# --- pattern tests ---

def test_dod_pass_count():
    assert len(dod_passes()) == 3

def test_dod_pass_values():
    p = dod_passes()
    assert p[0] == b"\x00"
    assert p[1] == b"\xff"
    assert p[2] is RANDOM

def test_gutmann_pass_count():
    assert len(gutmann_passes()) == 35

def test_gutmann_bookends_are_random():
    p = gutmann_passes()
    assert all(x is RANDOM for x in p[:4])
    assert all(x is RANDOM for x in p[-4:])

def test_gutmann_middle_is_fixed():
    p = gutmann_passes()
    assert all(isinstance(x, bytes) for x in p[4:31])

def test_random_passes_length():
    assert len(random_passes(7)) == 7
    assert all(x is RANDOM for x in random_passes(7))

def test_tile_single_byte():
    assert _tile(b"\xab", 4) == b"\xab\xab\xab\xab"

def test_tile_non_divisible():
    result = _tile(b"\x12\x34", 5)
    assert result == b"\x12\x34\x12\x34\x12"

def test_tile_three_byte_pattern():
    result = _tile(b"\x92\x49\x24", 7)
    assert result == b"\x92\x49\x24\x92\x49\x24\x92"


# --- integration tests ---

def _tmpfile(content: bytes) -> str:
    fd, path = tempfile.mkstemp()
    os.write(fd, content)
    os.close(fd)
    return path


def test_file_is_gone_after_shred():
    path = _tmpfile(b"sensitive data here")
    Shredder().shred(path, dod_passes())
    assert not os.path.exists(path)

def test_verify_mode_passes():
    path = _tmpfile(b"A" * 8192)
    Shredder(verify=True).shred(path, dod_passes())
    assert not os.path.exists(path)

def test_zero_byte_file():
    path = _tmpfile(b"")
    Shredder().shred(path, dod_passes())
    assert not os.path.exists(path)

def test_gutmann_method():
    path = _tmpfile(b"gutmann test" * 100)
    Shredder().shred(path, gutmann_passes())
    assert not os.path.exists(path)

def test_random_method():
    path = _tmpfile(b"random test" * 50)
    Shredder().shred(path, random_passes(5))
    assert not os.path.exists(path)

def test_large_file():
    path = _tmpfile(os.urandom(1024 * 1024))
    Shredder().shred(path, dod_passes())
    assert not os.path.exists(path)

def test_directory_shred(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"file a")
    (tmp_path / "b.txt").write_bytes(b"file b")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.txt").write_bytes(b"nested file")

    Shredder().shred_directory(str(tmp_path), dod_passes())
    assert not tmp_path.exists()

def test_verbose_output(capsys):
    path = _tmpfile(b"some content")
    Shredder(verbose=True).shred(path, dod_passes())
    assert "deleted" in capsys.readouterr().out
