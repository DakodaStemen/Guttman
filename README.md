# Guttman

A command-line utility for secure file deletion on Linux. Guttman overwrites file contents with deterministic and random byte patterns before unlinking the inode, implementing the DoD 5220.22-M standard and Peter Gutmann's 35-pass method from his 1996 paper.

[![Python](https://img.shields.io/badge/Python-3.6+-3776AB.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Table of Contents

- [Background](#background)
- [Threat Model](#threat-model)
- [Installation](#installation)
- [Usage](#usage)
- [Overwrite Methods](#overwrite-methods)
- [How It Works](#how-it-works)
- [Edge Cases and Safety Guarantees](#edge-cases-and-safety-guarantees)
- [Running Tests](#running-tests)
- [Project Layout](#project-layout)
- [License](#license)

---

## Background

Standard file deletion on Linux removes the directory entry and marks the inode and data blocks as free — the actual file data stays on disk until those blocks are overwritten by a future write. On a lightly used filesystem, sensitive data can sit readable in "free" space for days, weeks, or indefinitely.

Guttman makes the overwrite happen intentionally and immediately, using patterns documented in Peter Gutmann's 1996 paper *"Secure Deletion of Data from Magnetic and Solid-State Memory"* (USENIX Security Symposium) and the U.S. Department of Defense's sanitization standard DoD 5220.22-M.

After all overwrite passes complete, the file is truncated to zero bytes, then unlinked. The directory entry disappears last, after the data has been overwritten.

---

## Threat Model

### Magnetic Hard Drives (HDDs)

Guttman is most effective on spinning disk. On HDDs with no bad-sector remapping and no journaling that duplicates data, overwrite-based deletion is reliable and well-studied. The DoD 3-pass method is accepted by most security standards as sufficient for classified material.

The Gutmann 35-pass method targets encoding-specific residues on older MFM/RLL/PRML drives. The 27 fixed patterns in the middle of the sequence are specifically designed to cancel out the encoding artifacts those heads leave behind. On modern drives (post-~2001), which universally use PRML encoding at higher densities, only the random passes at the start and end of the Gutmann sequence remain meaningful — but the 35-pass method remains available for completeness and compliance contexts.

### SSDs and Copy-on-Write Filesystems

**Overwrite-based deletion cannot guarantee physical sector erasure on SSDs, btrfs, or ZFS.** Two mechanisms break the assumption:

1. **SSD wear leveling:** The flash controller remaps logical block addresses to physical cells to distribute writes. An overwrite to logical block N may be written to a different physical cell, leaving the original cell intact until the controller reclaims it.

2. **Copy-on-write semantics (btrfs, ZFS):** CoW filesystems never overwrite data in place. A write to an existing block allocates a new block and updates the pointer, leaving the old block accessible in free space until it is garbage-collected.

If your threat model requires assured erasure on SSDs or CoW filesystems, the correct approach is full-disk encryption (LUKS, dm-crypt) combined with key destruction. Encrypt before you store sensitive data; secure deletion then becomes a matter of overwriting or discarding the encryption key — a 32-byte operation guaranteed to be effective.

---

## Installation

No dependencies outside the standard library.

```bash
git clone https://github.com/DakodaStemen/Guttman.git
cd Guttman
python3 guttman.py --help
```

**Install as a system command:**

```bash
chmod +x guttman.py
sudo ln -s "$(pwd)/guttman.py" /usr/local/bin/guttman
```

---

## Usage

```
guttman [-m METHOD] [-p N] [-v] [--verify] [-r] FILE [FILE ...]

Arguments:
  FILE              One or more files to shred. Directories require -r.

Options:
  -m, --method      Overwrite method: dod, gutmann, random (default: dod)
  -p, --passes N    Number of passes for --method=random (default: 3)
  -v, --verbose     Print each pass name/number as it executes
      --verify      After each deterministic pass, read back and compare bytes
  -r, --recursive   Recursively shred all files under a directory
```

### Examples

```bash
# DoD 3-pass with readback verification
guttman --verify -v secrets.txt

# Gutmann 35-pass on a directory tree
guttman -m gutmann -r -v ./private/

# 10 random passes on multiple files
guttman -m random -p 10 key.pem cert.pem

# Pipe a file list from find
find /tmp/scratch -type f | xargs guttman -m dod

# Shred and verify a single file, silent
guttman --verify /home/user/.ssh/id_rsa
```

---

## Overwrite Methods

### `dod` — DoD 5220.22-M (default)

3 passes. The U.S. Department of Defense sanitization standard for clearing magnetic storage media.

| Pass | Pattern |
|------|---------|
| 1 | `0x00` — all zeros |
| 2 | `0xFF` — all ones |
| 3 | Random bytes from `os.urandom` |

Each pass is followed by `fsync`. The random final pass ensures the last written data on disk is not a predictable pattern.

### `gutmann` — Gutmann 35-pass

35 passes. Implements the full sequence from Peter Gutmann's 1996 paper, designed to address encoding artifacts on a broad range of magnetic recording techniques.

| Passes | Pattern |
|--------|---------|
| 1–4 | Random bytes (os.urandom) |
| 5–11 | Fixed: 0x55, 0xAA, 0x92/0x49/0x24, 0x49/0x24/0x92, 0x24/0x92/0x49 |
| 12–27 | Fixed patterns targeting specific MFM/RLL/PRML encoding artifacts |
| 28–31 | Remaining fixed patterns |
| 32–35 | Random bytes (os.urandom) |

The 27 middle fixed patterns are only meaningful for drives using the specific encoding they target. On modern PRML drives, the 4+4 random passes at the boundaries provide the useful work; the 27 fixed passes are included for completeness and compliance.

### `random` — Random N-pass

`N` passes (configurable with `-p`). Each pass writes a fresh `os.urandom` buffer to the entire file. Use this when you want more than 3 passes but do not need the specific Gutmann patterns.

---

## How It Works

### Raw File Descriptors

Files are opened with `os.open` using raw POSIX file descriptors rather than Python's buffered I/O (`open()`). Python's buffered layer can hold data in a userspace buffer and delay the actual write syscall — unacceptable when the goal is to ensure bytes reach the kernel write path on every pass. `os.write` on a raw fd bypasses this buffer.

### fsync Per Pass

After writing every pass, `os.fsync(fd)` is called before proceeding to the next. `fsync` flushes the kernel's page cache for that file descriptor to the storage device's write cache. It does not guarantee that the drive's internal write cache has been flushed to platters (that requires the drive to issue a FLUSH CACHE command), but it is the strongest guarantee available at the userspace level without raw device access.

### Truncate Then Unlink

After all passes complete:
1. The file is truncated to zero bytes with `os.ftruncate`.
2. The file descriptor is closed.
3. The file is unlinked with `os.unlink`.

Truncating first ensures the inode's block pointers are cleared before the directory entry is removed. On most filesystems, this is redundant (the data was already overwritten), but it removes ambiguity in the filesystem's free-block accounting.

### Pattern Generation

Deterministic patterns (DoD passes 1–2, all Gutmann fixed passes) are generated by `patterns.py` using `bytes([value]) * block_size`. Random passes use `os.urandom(block_size)` for each block, ensuring cryptographically random data from the OS entropy pool.

The overwrite is written in blocks (default 1 MB) rather than the entire file at once to keep memory usage bounded regardless of file size.

---

## Edge Cases and Safety Guarantees

### Symlinks

Symlinks are resolved to their real path via `os.path.realpath` before shredding. The resolved path is what gets overwritten. Guttman will not follow a symlink to a file outside the paths you specify.

### Read-Only Files

If a file's permissions do not allow writing, Guttman `chmod`s it writable (`stat.S_IRUSR | stat.S_IWUSR`) before overwriting, then proceeds normally. The inode permissions are restored to read-only after shredding, then the file is unlinked.

### Interrupted Shreds

If a shred is interrupted mid-pass (SIGINT, power loss, etc.), the file will be in an indeterminate state: some passes may be complete, the current pass may be partial, and subsequent passes have not run. The file **should not be assumed securely deleted** in this state. A warning is printed if an exception is caught mid-shred. Re-running Guttman on the file will start a fresh shred sequence.

### Directories

With `-r`, Guttman descends into directories recursively. Files are shredded in directory-walk order. After all files in a directory are shredded, the (now-empty) directory is removed with `os.rmdir`. Symlinks encountered during recursive traversal are treated as files (the symlink itself is removed, but the link target is not followed).

---

## Running Tests

```bash
python3 -m pytest tests/ -v
```

Tests cover:
- DoD, Gutmann, and random pass sequences
- File truncation and unlinking
- Verification pass correctness
- Symlink resolution
- Recursive directory shredding
- Interrupt handling (partial shred detection)

---

## Project Layout

```
Guttman/
├── guttman.py        CLI entry point, argument parsing, shred orchestration
├── shredder.py       Core shredder: file open, pass loop, fsync, truncate, unlink
├── patterns.py       Pattern generation for DoD and Gutmann pass sequences
├── tests/            pytest test suite
└── README.md
```

---

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2021–2026 Dakoda Stemen