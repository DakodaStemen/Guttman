# Guttman

**Best-effort secure file shredder for Linux with read-back verification and storage-aware warnings: tells you when overwriting cannot work (SSD, btrfs, ZFS) and what to use instead.**

[![CI](https://github.com/DakodaStemen/Guttman/actions/workflows/ci.yml/badge.svg)](https://github.com/DakodaStemen/Guttman/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Overwrites a file in place, optionally reads each pass back, scrubs the file name, then unlinks it. Pure standard library. **It refuses to run where overwriting cannot work**, and `guttman advise` prints the whole-device commands that do.

> [!CAUTION]
> ### When NOT to use Guttman
> Per-file overwrite is **not a reliable way to destroy data** on:
>
> | Situation | Why | Use instead |
> |---|---|---|
> | **SSD, NVMe, SD/eMMC, USB flash** | The flash translation layer remaps writes; old cells survive ([Wei et al., FAST'11](https://www.usenix.org/legacy/event/fast11/tech/full_papers/Wei.pdf)) | `nvme sanitize`, `hdparm --security-erase`, `blkdiscard -s`, or encrypt-then-destroy-key |
> | **btrfs, ZFS, bcachefs, f2fs, nilfs2** | Copy-on-write: writes go to new blocks, old ones are freed, not erased (see the [loop-mount test](tests/test_cow_loop.py)) | Device-level methods; delete snapshots |
> | **Snapshots, backups, journals, swap, caches** | Other copies exist outside the file | Handle each copy; full-disk encryption + key destruction |
> | **Storage guttman cannot identify** | Unknown means unsafe | `guttman advise` |
> | **Anything needing a compliance attestation** | Guttman is best-effort and uncertified | A sanitization process per [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final) |
>
> Guttman **exits with code 2** on the first four unless you pass `--force-unsafe`.

## Install

```bash
pip install git+https://github.com/DakodaStemen/Guttman.git   # gives you the `guttman` command
# or from a checkout
pip install -e ".[test]"
```

Python 3.10+, Linux. No runtime dependencies. (Not yet on PyPI; a Trusted Publishing workflow is prepared in `.github/workflows/publish.yml`.)

## Usage

```bash
guttman secret.txt                      # DoD-style 3 passes, if storage is suitable
guttman --readback secret.txt           # + read each pass back and compare
guttman -n -r ./private/                # dry run: plan, warnings and refusals; changes nothing
guttman --strict --report out.json f    # any warning => exit 2, JSON report
guttman advise /path/or/dev/nvme0n1     # print (never run) the right sanitize commands
guttman --force-unsafe secret.txt       # override the refusal (you accept it may not work)
```

What a refusal looks like (real output from a dry run on an NVMe-backed ext4 volume):

```text
$ guttman -n ./scratch-dir
guttman: would refuse: ./scratch-dir: backing device is flash (SSD/NVMe): wear-levelling remaps
writes, so old cells can survive an overwrite. TRIM/discard is supported - run `fstrim` after
deleting, but TRIM is not a secure erase.
guttman: ./scratch-dir: overwriting is not reliable here. Run `guttman advise ./scratch-dir` for
what to do instead, or pass --force-unsafe to shred anyway.
$ echo $?
2
```

| Option | Meaning |
|---|---|
| `-m {dod,random,gutmann}` | method (default `dod`); `gutmann` is **legacy**, see below |
| `-p N` | pass count for `random` |
| `--readback` | read-back check after every pass (alias: `--verify`, deprecated name) |
| `-n`, `--dry-run` | report plan, warnings, refusals; modify nothing (exit 2 if it would refuse) |
| `--force-unsafe` | proceed on SSD/NVMe/CoW/unidentified storage |
| `--strict` | any warning is a failure: exit 2, nothing shredded for that target (wins over `--force-unsafe`) |
| `--report FILE` | JSON report (`-` = stdout) |
| `--io {buffered,sync,direct}` | `sync` = `O_SYNC` (default); `direct` = `O_DIRECT`+`O_SYNC` for aligned I/O, falls back with a note |
| `--no-scrub-names` | keep the original name at unlink time |
| `-q` | silence warnings and notes (never refusals) |
| `-r` | recurse into directories |
| `-v` | per-pass logging |

Exit codes: `0` ok · `1` failure (including read-back mismatch) · `2` refused by storage policy or `--strict` · `130` interrupted.

## Decision flow

```mermaid
flowchart TD
    A[guttman PATH] --> B{symlink?}
    B -- yes --> L[scrub name + unlink link only<br/>target untouched]
    B -- no --> C[detect storage:<br/>mountinfo + /sys]
    C --> D{SSD/NVMe, CoW or<br/>unknown storage?}
    D -- yes, no --force-unsafe --> R[REFUSE, exit 2<br/>suggest guttman advise]
    D -- no / forced --> S{--strict and<br/>any warning?}
    S -- yes --> R2[REFUSE, exit 2]
    S -- no --> E{--dry-run?}
    E -- yes --> P[print plan, exit]
    E -- no --> G[write pass N over allocated extents<br/>O_SYNC / O_DIRECT, fsync]
    G --> I{--readback?}
    I -- yes --> J[drop page cache, read back,<br/>compare BLAKE2b]
    J -- mismatch --> X[error: file kept, exit 1]
    J -- ok --> K
    I -- no --> K{more passes?}
    K -- yes --> G
    K -- no --> M[truncate to 0, fsync]
    M --> N[rename to random name x3,<br/>fsync dir, unlink]
```

## Methods

| Method | Passes | Sequence | Status |
|---|---|---|---|
| `dod` (default) | 3 | `0x00`, `0xFF`, random | DoD 5220.22-M as commonly implemented; superseded for media sanitization by NIST SP 800-88 |
| `random` | N | N random passes (`os.urandom`) | |
| `gutmann` | 35 | 4 random, 27 fixed patterns, 4 random | **Legacy.** Designed for 1990s MFM/RLL drive encodings. Adds time, not security, on modern media. Kept for compatibility only. |

Gutmann's own epilogue to the 1996 paper says SSDs "are a totally different technology than magnetic media, and require totally different deletion techniques" and that overwriting through the flash translation layer cannot be relied on ([source](https://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html)).

## `guttman advise`

Prints, **never executes**, the commands that fit the detected device, with a mapping to SP 800-88 *Clear* / *Purge* / *Destroy*:

```text
$ guttman advise /dev/nvme0n1          (excerpt)
NVMe (/dev/nvme0n1) - Purge:
  nvme id-ctrl /dev/nvme0 -H | grep -i sanicap     # which sanitize actions exist
  nvme sanitize /dev/nvme0 --sanact=4              # crypto erase (if supported)
  nvme sanitize /dev/nvme0 --sanact=2              # block erase (if supported)
  nvme sanitize-log /dev/nvme0                     # poll until finished
Any block device with discard support (/dev/nvme0n1):
  blkdiscard -s /dev/nvme0n1                  # secure discard; fails if unsupported
```

SATA gets `hdparm --user-master u --security-erase`; LUKS volumes get `cryptsetup luksErase`. All of these destroy the **whole device**; check the name, and verify the exact options against your device's documentation first.

## Read-back check

With `--readback`, after each pass the file is `fsync`ed, its page cache is dropped (`posix_fadvise(DONTNEED)`), and it is read back and compared to a BLAKE2b digest computed while writing (works for random passes without storing them). A mismatch keeps the file and exits 1.

> [!WARNING]
> The read-back check confirms what the OS/device **returns for that logical address**. It catches I/O errors and silent corruption. It does **not** prove physical erasure: a remapping layer (flash, CoW) can answer correctly while old copies remain.

## JSON report

`--report out.json` records, per target: status (`shredded`, `refused`, `dry-run`, `failed`, …), storage findings, and per file: size, bytes written, sparse flag, I/O mode, whether the read-back check ran, whether the name was scrubbed. Written with mode `0600`. It also carries the disclaimer above in a `note` field.

## Behaviour notes

- **Symlinks** are removed, never followed.
- **Hard links:** all names see the overwritten data; warns (fails under `--strict`).
- **Sparse files:** only allocated extents are overwritten, via `SEEK_DATA`/`SEEK_HOLE`.
- **File names** are renamed to random names (3 rounds) before unlink. Old names can persist in journals.
- **Read-only files** are made owner-writable, then shredded.
- **Interrupted shreds** leave indeterminate content; do not treat as deleted.
- **Recursive mode** checks the storage of the top-level path only.

Details and limits: [THREAT_MODEL.md](THREAT_MODEL.md) (adversary tiers, media matrix).

## Benchmarks

Measured with [`benchmarks/bench.py`](benchmarks/bench.py) on version 0.2.0 (one 64 MiB temp file per run, median of 3, `fsync` after every pass, includes the final unlink). **Not re-measured for 0.3.0**, which adds `O_SYNC` by default and name scrubbing; expect different numbers.

Environment: AMD Ryzen 7 5800H, Linux 7.0 x86_64, Python 3.14.7, ext4 on LVM over NVMe.

| Method | Passes | Median time | Effective MiB/s |
|---|---|---|---|
| dod | 3 | 1.77 s | 36 |
| dod + read-back | 3 | 2.27 s | 28 |
| random x3 | 3 | 3.11 s | 21 |
| gutmann (legacy) | 35 | 14.46 s | 4 |
| gutmann + read-back | 35 | 27.43 s | 2 |

## References

- NIST SP 800-88 Rev. 2, *Guidelines for Media Sanitization*, September 2025: <https://csrc.nist.gov/pubs/sp/800/88/r2/final>
- P. Gutmann, *Secure Deletion of Data from Magnetic and Solid-State Memory* (USENIX Security 1996), incl. epilogue: <https://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html>
- M. Wei et al., *Reliably Erasing Data From Flash-Based Solid State Drives*, USENIX FAST '11: <https://www.usenix.org/legacy/event/fast11/tech/full_papers/Wei.pdf>

> [!NOTE]
> **Spelling:** the project is *Guttman*; the method is named after cryptographer Peter **Gutmann**. The CLI flag is `--method gutmann`. The repo name is kept as-is.

## Development

```bash
pip install -e ".[test]" ruff
ruff check .
python -m pytest -rs        # loop-mount btrfs/ext4 tests need root or passwordless sudo, else they skip
```

```text
guttman/
├── cli.py        arguments, policy (refuse / --strict), report
├── shredder.py   write/read-back loop, sparse, O_SYNC/O_DIRECT, name scrubbing
├── advise.py     `guttman advise`: print-only sanitize commands
├── detect.py     SSD, CoW, journal, layered/network detection
├── patterns.py   DoD / Gutmann (legacy) / random
└── progress.py   progress bar
```

See also [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2021-2026 Dakoda Stemen.
