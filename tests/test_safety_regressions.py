"""G1-G6 safety regressions. All destructive targets live in pytest tmp_path.

Assumptions: top-level symlinks are refused, never followed or link-only
shredded; hardlinks have no override. Random-pass verification is optional.
G6 and regular-file controls deliberately describe already-supported behavior.
"""
import contextlib
import os
from pathlib import Path
import signal
import stat
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guttman
import shredder
from patterns import _tile
from shredder import Shredder


@pytest.fixture(autouse=True)
def isolated_board(tmp_path, monkeypatch):
    # Before any possible Hermes import (these tests do not import Hermes).
    assert not str(tmp_path.resolve()).startswith('/home/dakoda/.hermes')
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path / 'board'))
    monkeypatch.setenv('HERMES_KANBAN_DB', str(tmp_path / 'board' / 'kanban.db'))


@contextlib.contextmanager
def bounded(seconds=2):
    """A hang is an assertion failure, never an indefinitely wedged CI worker."""
    class Deadline(BaseException):
        pass
    def expired(_signum, _frame):
        raise Deadline()
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    except Deadline:
        pytest.fail('operation made no progress before bounded deadline')
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def cli(monkeypatch, *args):
    monkeypatch.setattr(sys, 'argv', ['guttman', *map(str, args)])
    return guttman.main()


def call_refusing(operation):
    """Allow any ordinary safety exception; preservation is checked separately."""
    try:
        operation()
    except Exception:
        return True
    return False


@pytest.mark.parametrize('empty', [False, True], ids=['nonempty', 'empty'])
def test_g1_default_recursive_file_symlink_refused(tmp_path, monkeypatch, empty):
    outside = tmp_path / 'outside'
    original = b'' if empty else b'outside must survive'
    outside.write_bytes(original)
    tree = tmp_path / 'tree'
    tree.mkdir()
    link = tree / 'link'
    link.symlink_to(outside)
    code = cli(monkeypatch, '-r', tree)
    assert outside.exists(), 'recursive shred followed symlink and deleted outside target'
    assert outside.read_bytes() == original
    assert link.is_symlink()
    assert code == 1, 'skipped symlink must produce a failing exit status'


@pytest.mark.parametrize('directory', [False, True], ids=['file', 'directory'])
def test_g1_default_top_level_symlink_refused(tmp_path, monkeypatch, directory):
    target = tmp_path / 'target'
    if directory:
        target.mkdir()
        data = target / 'data'
    else:
        data = target
    data.write_bytes(b'keep this')
    link = tmp_path / 'link'
    link.symlink_to(target, target_is_directory=directory)
    code = cli(monkeypatch, '-r', link)
    assert data.exists(), 'top-level symlink must not be followed'
    assert data.read_bytes() == b'keep this'
    assert link.is_symlink()
    assert code == 1


@pytest.mark.parametrize('empty', [False, True], ids=['nonempty', 'empty'])
def test_g1_default_recursive_hardlink_refused(tmp_path, monkeypatch, empty):
    outside = tmp_path / 'outside'
    original = b'' if empty else b'multiply linked data'
    outside.write_bytes(original)
    tree = tmp_path / 'tree'
    tree.mkdir()
    alias = tree / 'alias'
    os.link(outside, alias)
    code = cli(monkeypatch, '-r', tree)
    assert outside.read_bytes() == original, 'hardlink shred modified the other name'
    assert alias.exists(), 'refused hardlink must not be unlinked, even when empty'
    assert code == 1


def test_g1_fifo_refused_without_unlink_or_hang(tmp_path):
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    with bounded():
        refused = call_refusing(lambda: Shredder().shred(str(fifo), [b'\x00']))
    assert refused, 'FIFO must be refused, not treated as an empty regular file'
    assert stat.S_ISFIFO(fifo.lstat().st_mode)


def test_g1_directory_direct_api_refused(tmp_path):
    directory = tmp_path / 'directory'
    directory.mkdir()
    with bounded():
        assert call_refusing(lambda: Shredder().shred(str(directory), [b'\x00']))
    assert directory.is_dir()


def test_g1_replaced_entry_not_unlinked(tmp_path, monkeypatch):
    path = tmp_path / 'data'
    path.write_bytes(b'original inode')
    saved = tmp_path / 'opened-inode'
    original_write = Shredder._write_pass
    def replace_after_write(self, fd, size, pat):
        original_write(self, fd, size, pat)
        path.rename(saved)
        path.write_bytes(b'replacement must survive')
    monkeypatch.setattr(Shredder, '_write_pass', replace_after_write)
    call_refusing(lambda: Shredder().shred(str(path), [b'\x00']))
    assert path.exists(), 'unlink removed a different inode from the opened file'
    assert path.read_bytes() == b'replacement must survive'


def test_g2_recursive_file_failure_propagates_and_continues(tmp_path, monkeypatch, capsys):
    tree = tmp_path / 'tree'
    tree.mkdir()
    bad = tree / 'bad'
    good = tree / 'good'
    bad.write_bytes(b'cannot shred')
    good.write_bytes(b'can shred')
    actual = Shredder.shred
    def fail_one(self, path, passes):
        if Path(path).name == 'bad':
            raise PermissionError('injected unshreddable file')
        return actual(self, path, passes)
    monkeypatch.setattr(Shredder, 'shred', fail_one)
    # Deliberately visit bad before good to prove failure doesn't abort the walk.
    actual_walk = os.walk
    def ordered_walk(*args, **kwargs):
        for root, dirs, files in actual_walk(*args, **kwargs):
            yield root, dirs, sorted(files)
    monkeypatch.setattr(shredder.os, 'walk', ordered_walk)
    code = cli(monkeypatch, '-r', tree)
    assert not good.exists(), 'other files must still be processed after a refusal'
    assert bad.read_bytes() == b'cannot shred'
    assert 'injected unshreddable file' in capsys.readouterr().err
    assert code == 1, 'recursive failure was swallowed by CLI'


def test_g2_recursive_rmdir_failure_propagates(tmp_path, monkeypatch, capsys):
    tree = tmp_path / 'tree'
    tree.mkdir()
    (tree / 'data').write_bytes(b'data')
    actual = os.rmdir
    def fail_tree(path, *args, **kwargs):
        if os.fspath(path) == str(tree):
            raise PermissionError('injected rmdir failure')
        return actual(path, *args, **kwargs)
    monkeypatch.setattr(shredder.os, 'rmdir', fail_tree)
    code = cli(monkeypatch, '-r', tree)
    assert not (tree / 'data').exists()
    assert tree.exists()
    assert 'injected rmdir failure' in capsys.readouterr().err
    assert code == 1, 'rmdir failure was swallowed by CLI'


@pytest.mark.parametrize('pattern', [b'\x00', b'\x92\x49\x24'], ids=['single', 'three-byte'])
def test_g3_short_writes_complete_entire_pass(tmp_path, monkeypatch, pattern):
    path = tmp_path / 'data'
    size = 2 * shredder.BLOCK + 17
    path.write_bytes(b'X' * size)
    actual = os.write
    calls = []
    def short_write(fd, buf):
        count = max(1, len(buf) // 2)
        calls.append(count)
        return actual(fd, buf[:count])
    monkeypatch.setattr(shredder.os, 'write', short_write)
    with path.open('r+b') as stream:
        Shredder()._write_pass(stream.fileno(), size, pattern)
    assert calls, 'injected short-write path was not exercised'
    # The established pass API tiles each BLOCK independently.
    expected = b''.join(_tile(pattern, min(shredder.BLOCK, size - offset))
                        for offset in range(0, size, shredder.BLOCK))
    assert path.read_bytes() == expected, 'short writes left original or wrong bytes behind'


def test_g3_zero_write_raises_without_unlink(tmp_path, monkeypatch):
    path = tmp_path / 'data'
    path.write_bytes(b'must remain')
    calls = []
    def zero(fd, buf):
        calls.append(len(buf))
        return 0
    monkeypatch.setattr(shredder.os, 'write', zero)
    with bounded():
        refused = call_refusing(lambda: Shredder().shred(str(path), [b'\x00']))
    assert calls
    assert refused, 'zero-progress write must raise'
    assert path.exists(), 'failed overwrite must not unlink the file'
    assert path.read_bytes() == b'must remain'


@pytest.mark.parametrize('original', [b'data', b''], ids=['nonempty', 'empty'])
def test_g4_symlink_swap_before_open_refused(tmp_path, monkeypatch, original):
    path = tmp_path / 'data'
    path.write_bytes(original)
    outside = tmp_path / 'outside'
    outside.write_bytes(b'outside must survive')
    actual = os.open
    swapped = []
    def swapping_open(name, flags, *args, **kwargs):
        if os.fspath(name) in (str(path), path.name) and not swapped:
            path.unlink()
            path.symlink_to(outside)
            swapped.append(True)
        return actual(name, flags, *args, **kwargs)
    monkeypatch.setattr(shredder.os, 'open', swapping_open)
    refused = call_refusing(lambda: Shredder().shred(str(path), [b'\x00']))
    assert swapped, 'empty files must also go through descriptor-based type checks'
    assert outside.exists(), 'open followed swapped symlink and deleted its target'
    assert outside.read_bytes() == b'outside must survive'
    assert refused, 'symlink swap must be refused'


def test_g4_chmod_must_not_touch_swapped_symlink_target(tmp_path, monkeypatch):
    path = tmp_path / 'data'
    path.write_bytes(b'data')
    path.chmod(0o400)
    outside = tmp_path / 'outside'
    outside.write_bytes(b'keep')
    outside.chmod(0o400)
    actual_access = os.access
    swapped = []
    def swap_on_path_permission_check(name, mode, *args, **kwargs):
        if os.fspath(name) == str(path) and not swapped:
            path.unlink()
            path.symlink_to(outside)
            swapped.append(True)
            return False
        return actual_access(name, mode, *args, **kwargs)
    monkeypatch.setattr(shredder.os, 'access', swap_on_path_permission_check)
    call_refusing(lambda: Shredder().shred(str(path), [b'\x00']))
    assert outside.exists(), 'pathname permission check allowed unrelated target deletion'
    assert stat.S_IMODE(outside.stat().st_mode) == 0o400
    assert outside.read_bytes() == b'keep'


def test_g4_size_taken_from_opened_inode(tmp_path, monkeypatch):
    path = tmp_path / 'data'
    path.write_bytes(b'x')
    replacement = b'long replacement data'
    actual_open = os.open
    actual_truncate = os.ftruncate
    swapped = []
    observed = []
    def swap_regular(name, flags, *args, **kwargs):
        if os.fspath(name) in (str(path), path.name) and not swapped:
            path.unlink()
            path.write_bytes(replacement)
            swapped.append(True)
        return actual_open(name, flags, *args, **kwargs)
    def inspect_before_truncate(fd, size):
        observed.append(os.pread(fd, len(replacement), 0))
        return actual_truncate(fd, size)
    monkeypatch.setattr(shredder.os, 'open', swap_regular)
    monkeypatch.setattr(shredder.os, 'ftruncate', inspect_before_truncate)
    Shredder().shred(str(path), [b'\x00'])
    assert swapped and observed
    assert observed == [b'\x00' * len(replacement)], 'pre-open stat left tail unoverwritten'


def test_g4_readonly_regular_file_still_shredded(tmp_path):
    path = tmp_path / 'readonly'
    path.write_bytes(b'data')
    path.chmod(0o400)
    Shredder().shred(str(path), [b'\x00'])
    assert not path.exists()


@pytest.mark.parametrize('short_first', [False, True], ids=['empty-read', 'short-then-eof'])
def test_g5_truncated_verification_raises_without_hang_or_unlink(tmp_path, monkeypatch, short_first):
    path = tmp_path / 'data'
    path.write_bytes(b'X' * 64)
    actual_read = os.read
    calls = []
    def truncate_mid_verify(fd, count):
        calls.append(count)
        if short_first and len(calls) == 1:
            result = actual_read(fd, count // 2)
            os.ftruncate(fd, count // 2)
            return result
        os.ftruncate(fd, 0)
        return b''
    monkeypatch.setattr(shredder.os, 'read', truncate_mid_verify)
    with bounded():
        refused = call_refusing(lambda: Shredder(verify=True).shred(str(path), [b'\x00']))
    assert calls
    assert refused, 'short/empty verification read must raise'
    assert path.exists(), 'failed verification must not unlink'


def test_g5_positive_short_read_is_verification_failure(tmp_path, monkeypatch):
    path = tmp_path / 'data'
    path.write_bytes(b'\x00' * 64)
    actual = os.read
    calls = []
    def short_read(fd, size):
        calls.append(size)
        return actual(fd, max(1, size // 2))
    monkeypatch.setattr(shredder.os, 'read', short_read)
    with path.open('rb') as stream, bounded():
        refused = call_refusing(lambda: Shredder()._verify_pass(stream.fileno(), 64, b'\x00'))
    assert calls
    assert refused, 'short read was accepted as a complete verification chunk'


def test_g6_observe_overwrite_before_truncation_and_unlink(tmp_path, monkeypatch):
    path = tmp_path / 'data'
    original = b'sensitive bytes' * 400
    path.write_bytes(original)
    actual_unlink = os.unlink
    actual_truncate = os.ftruncate
    overwritten = []
    before_unlink = []
    def capture_truncate(fd, size):
        overwritten.append(os.pread(fd, len(original), 0))
        return actual_truncate(fd, size)
    def capture_unlink(name, *args, **kwargs):
        if os.fspath(name) in (str(path), path.name):
            before_unlink.append(path.read_bytes())
        return actual_unlink(name, *args, **kwargs)
    monkeypatch.setattr(shredder.os, 'ftruncate', capture_truncate)
    monkeypatch.setattr(shredder.os, 'unlink', capture_unlink)
    Shredder().shred(str(path), [b'\xa5'])
    assert overwritten == [b'\xa5' * len(original)], 'must observe actual overwrite, not just deletion'
    assert before_unlink and all(data != original for data in before_unlink)
    assert not path.exists()


def test_g6_keyboardinterrupt_reports_indeterminate_and_exit130(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'data'
    path.write_bytes(b'sensitive bytes')
    actual_write = os.write
    calls = []
    def interrupt_mid_pass(self, fd, size, pat):
        calls.append(actual_write(fd, b'\x00'))
        raise KeyboardInterrupt()
    monkeypatch.setattr(Shredder, '_write_pass', interrupt_mid_pass)
    code = cli(monkeypatch, path)
    assert calls == [1]
    assert code == 130
    assert path.exists()
    assert path.read_bytes() == b'\x00ensitive bytes'
    message = capsys.readouterr().err.lower()
    assert 'indeterminate' in message
    assert 'do not treat as securely deleted' in message
