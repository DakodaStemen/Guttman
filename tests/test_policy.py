"""Fail-closed policy, --strict, --report, advise dispatch."""
import json

import pytest

from guttman import cli, detect


def _f(level, code, msg="x"):
    return detect.Finding(level, code, msg)


def _patch(monkeypatch, findings):
    monkeypatch.setattr(cli, "analyze_path", lambda path: list(findings))


@pytest.mark.parametrize("code", ["ssd", "cow", "unknown-fs", "device-unknown", "unsupported"])
def test_refuses_blocking_storage(tmp_path, monkeypatch, code):
    _patch(monkeypatch, [_f("warn" if code in ("ssd", "cow") else "info", code)])
    f = tmp_path / "a"
    f.write_bytes(b"secret")
    assert cli.main(["-q", str(f)]) == cli.EXIT_REFUSED
    assert f.read_bytes() == b"secret"          # untouched


def test_quiet_does_not_hide_refusal(tmp_path, monkeypatch, capsys):
    _patch(monkeypatch, [_f("warn", "ssd", "flash")])
    f = tmp_path / "a"
    f.write_bytes(b"s")
    cli.main(["-q", str(f)])
    assert "refusing" in capsys.readouterr().err


def test_force_unsafe_overrides(tmp_path, monkeypatch):
    _patch(monkeypatch, [_f("warn", "ssd")])
    f = tmp_path / "a"
    f.write_bytes(b"s")
    assert cli.main(["-q", "--force-unsafe", str(f)]) == 0
    assert not f.exists()


def test_dry_run_reports_refusal_and_changes_nothing(tmp_path, monkeypatch, capsys):
    _patch(monkeypatch, [_f("warn", "cow")])
    f = tmp_path / "a"
    f.write_bytes(b"s")
    assert cli.main(["-n", str(f)]) == cli.EXIT_REFUSED
    assert "would refuse" in capsys.readouterr().err and f.exists()


def test_non_blocking_warning_proceeds_without_strict(tmp_path, monkeypatch):
    _patch(monkeypatch, [_f("warn", "network")])
    f = tmp_path / "a"
    f.write_bytes(b"s")
    assert cli.main(["-q", str(f)]) == 0 and not f.exists()


def test_strict_fails_on_any_warning_and_shreds_nothing(tmp_path, monkeypatch):
    _patch(monkeypatch, [_f("warn", "network")])
    f = tmp_path / "a"
    f.write_bytes(b"s")
    assert cli.main(["-q", "--strict", str(f)]) == cli.EXIT_REFUSED
    assert f.exists()


def test_strict_wins_over_force_unsafe(tmp_path, monkeypatch):
    _patch(monkeypatch, [_f("warn", "ssd")])
    f = tmp_path / "a"
    f.write_bytes(b"s")
    assert cli.main(["-q", "--strict", "--force-unsafe", str(f)]) == cli.EXIT_REFUSED
    assert f.exists()


def test_strict_fails_on_engine_warning_hardlink(tmp_path, monkeypatch):
    _patch(monkeypatch, [])
    a = tmp_path / "a"
    a.write_bytes(b"s")
    (tmp_path / "b").hardlink_to(a)
    assert cli.main(["-q", "--strict", str(a)]) == cli.EXIT_REFUSED


def test_strict_clean_passes(tmp_path, monkeypatch):
    _patch(monkeypatch, [_f("info", "journal")])
    f = tmp_path / "a"
    f.write_bytes(b"s")
    assert cli.main(["-q", "--strict", str(f)]) == 0


def test_report_json(tmp_path, monkeypatch):
    _patch(monkeypatch, [])
    f = tmp_path / "a"
    f.write_bytes(b"x" * 5000)
    rep = tmp_path / "rep.json"
    assert cli.main(["-q", "--readback", "--report", str(rep), str(f)]) == 0
    r = json.loads(rep.read_text())
    assert r["tool"] == "guttman" and r["method"] == "dod" and r["passes"] == 3
    res = r["results"][0]
    assert res["status"] == "shredded"
    fr = res["files"][0]
    assert fr["readback_checked"] is True and fr["size"] == 5000 and fr["bytes_written"] == 15000
    assert fr["renamed"] is True
    assert "not evidence" in r["note"]
    assert (rep.stat().st_mode & 0o777) == 0o600


def test_report_records_refusal(tmp_path, monkeypatch):
    _patch(monkeypatch, [_f("warn", "ssd")])
    f = tmp_path / "a"
    f.write_bytes(b"x")
    rep = tmp_path / "r.json"
    cli.main(["-q", "--report", str(rep), str(f)])
    r = json.loads(rep.read_text())
    assert r["results"][0]["status"] == "refused" and r["summary"]["refused"] == 1


def test_gutmann_is_labelled_legacy(tmp_path, monkeypatch, capsys):
    _patch(monkeypatch, [])
    f = tmp_path / "a"
    f.write_bytes(b"x")
    cli.main(["-m", "gutmann", "-n", str(f)])
    assert "legacy" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "LEGACY" in capsys.readouterr().out


def test_verify_alias_still_works(tmp_path, monkeypatch):
    _patch(monkeypatch, [])
    f = tmp_path / "a"
    f.write_bytes(b"x")
    assert cli.main(["-q", "--verify", str(f)]) == 0
