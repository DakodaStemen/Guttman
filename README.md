# Guttman

Command-line utility for secure file deletion on Linux. Overwrites file contents with deterministic and random byte patterns before unlinking the inode, implementing the DoD 5220.22-M and Gutmann 35-pass standards.

## Background

Standard file deletion removes the directory entry and marks blocks as free — the data itself stays on disk until overwritten by something else. Guttman makes sure that overwrite happens intentionally, using patterns documented in Peter Gutmann's 1996 paper "Secure Deletion of Data from Magnetic and Solid-State Memory."

**SSDs and copy-on-write filesystems (btrfs, ZFS):** overwrite-based deletion cannot guarantee physical sector erasure due to wear leveling and CoW semantics. If that threat model matters to you, use full-disk encryption (LUKS) and rely on key destruction rather than data overwriting.

## Usage

```
guttman [-m METHOD] [-p N] [-v] [--verify] [-r] FILE [FILE ...]
```

```
-m, --method    overwrite method: dod, gutmann, random (default: dod)
-p, --passes    pass count for --method=random (default: 3)
-v, --verbose   print each pass as it runs
    --verify    read back and verify each deterministic pass
-r, --recursive recursively shred a directory
```

## Examples

```bash
# DoD 3-pass with verification
guttman --verify -v secrets.txt

# Gutmann 35-pass on a directory
guttman -m gutmann -r -v ./private/

# 10 random passes on multiple files
guttman -m random -p 10 key.pem cert.pem

# Pipe from find
find /tmp/scratch -type f | xargs guttman -m dod
```

## Methods

| Method | Passes | Description |
|--------|--------|-------------|
| `dod` | 3 | DoD 5220.22-M: 0x00, 0xFF, random |
| `gutmann` | 35 | Gutmann 1996: 4 random, 27 encoding-targeted fixed patterns, 4 random |
| `random` | N | N passes of `os.urandom` (configurable with `-p`) |

## Installation

No dependencies outside the standard library.

```bash
git clone https://github.com/DakodaStemen/Guttman.git
cd Guttman
python3 guttman.py --help
```

To install as a system command:

```bash
chmod +x guttman.py
sudo ln -s "$(pwd)/guttman.py" /usr/local/bin/guttman
```

## Running Tests

```bash
python3 -m pytest tests/ -v
```

## How It Works

Files are opened with raw OS file descriptors (`os.open`) rather than Python's buffered I/O to avoid kernel buffering obscuring whether writes reach disk. Each pass calls `os.fsync` before moving to the next. After all passes, the file is truncated to zero and then unlinked.

Symlinks are resolved to their real path before shredding. Read-only files are chmod'd writable before overwriting. If a shred is interrupted mid-pass, a warning is printed — the file should be considered in an indeterminate state and not assumed securely deleted.

## License

MIT
