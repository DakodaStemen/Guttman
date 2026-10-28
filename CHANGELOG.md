# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [0.3.0] - Unreleased

### Changed (behaviour)
- **Fail-closed by default:** guttman now refuses (exit 2) on SSD/NVMe,
  copy-on-write filesystems (btrfs, ZFS, bcachefs, f2fs, nilfs2) and storage it
  cannot identify. Override with `--force-unsafe`. `-q` does not hide refusals.
- `--strict`: any warning becomes a failure (exit 2) and nothing is shredded for
  that target. Wins over `--force-unsafe`.
- Files are renamed to random names (3 rounds) before unlinking; directories likewise.
  Disable with `--no-scrub-names`.
- Writes use `O_SYNC` by default; `--io direct` adds `O_DIRECT` for aligned I/O
  with a noted fallback; `--io buffered` restores the old behaviour.
- Sparse files: only allocated extents are overwritten (`SEEK_DATA`/`SEEK_HOLE`).
- "Verify" is now "read-back check": `--readback` (`--verify` kept as a hidden alias).
  `VerifyError` is now `ReadbackError` (old name kept as an alias).
- `gutmann` method is labelled **legacy** and prints a note.
- Exit code 2 added for policy refusals / `--strict`.

### Added
- `guttman advise PATH|DEVICE`: prints (never runs) `nvme sanitize`,
  `hdparm --security-erase`, `blkdiscard -s`, `cryptsetup luksErase` with an
  SP 800-88 Clear/Purge mapping.
- `--report FILE|-`: JSON report (per-file status, bytes, read-back flag, I/O mode, findings).
- `THREAT_MODEL.md`, `SECURITY.md`.
- Loop-mount tests demonstrating the btrfs copy-on-write limitation against an
  ext4 control (skip with a reason when root/loop/mkfs are unavailable).
- CI: ruff, pip-audit, build check. Trusted-publishing release workflow (not run).

### Removed
- `docs/demo.gif` / `docs/demo.sh` (replaced by Markdown-native examples).

## [0.2.0]
- Package layout, dry-run, progress, storage warnings, read-back per pass, CI fix, docs.

## [0.1.0]
- Initial release.
