# Guttman threat model

Guttman is a **best-effort, file-level overwrite tool**. It writes patterns
through the normal Linux file API. Whether that destroys the old bytes depends
on every layer below it (filesystem, volume manager, device firmware). This
document says what it does and does not defend against.

## What guttman can and cannot control

| Layer | Overwrite-in-place honoured? | How guttman handles it |
|---|---|---|
| Rotational disk + in-place filesystem (ext4, xfs) | Yes, for file *contents* | Proceeds. Names are renamed before unlink; old names/timestamps may persist in the journal. |
| Flash (SSD, NVMe, SD/eMMC, USB stick) | No: the flash translation layer remaps writes (Wei et al., FAST'11) | **Refuses** unless `--force-unsafe`. |
| Copy-on-write / log-structured FS (btrfs, ZFS, bcachefs, f2fs, nilfs2) | No: writes go to new blocks, old ones are freed not erased | **Refuses** unless `--force-unsafe`. |
| Storage guttman cannot identify | Unknown | **Refuses** unless `--force-unsafe`. |
| tmpfs / overlayfs / network or FUSE filesystems | Not the device you think | Warns; `--strict` turns the warning into a failure. |
| Snapshots, backups, thumbnails, swap, editor temp files, other hard links | Out of scope: other copies exist | Warns about hard links; cannot see the rest. |

Detection is heuristic (`/proc/self/mountinfo`, `/sys/block/*/queue`). A
missing warning is **not** a guarantee.

## Adversary tiers

| Tier | Adversary | Typical capability | Guttman helps? |
|---|---|---|---|
| T0 | Casual / undelete | `ls`, trash, `extundelete`-style recovery of unlinked files from a live or imaged disk | Yes (on rotational, in-place storage). Overwrite + unlink removes the contents from the logical address space. |
| T1 | Forensic examiner with the **whole disk as a block device** | Reads every logical block, journals, free space, snapshots | Only if the data was overwritten in place and no snapshot/journal/backup copy exists. Not on CoW filesystems. Not for metadata left in journals. |
| T2 | Examiner who can bypass the device firmware (chip-off, FTL bypass, vendor tools) | Reads raw flash cells or remapped sectors | **No.** Per-file overwrite cannot reach remapped or over-provisioned flash. Use device sanitize or cryptographic erase (`guttman advise`). |
| T3 | Laboratory analysis of the physical medium | Specialised equipment beyond normal read channels | Out of scope. Guttman makes no claim here; consult SP 800-88 Rev. 2 for Purge / Destroy guidance. |

## Media matrix: what to use

Mapping to NIST SP 800-88 Rev. 2 terms (Clear / Purge / Destroy). This is a
summary for orientation, not a compliance statement; read the publication for
normative wording.

| Media | Single file | Whole device (re-use) | Whole device (retire) |
|---|---|---|---|
| HDD, in-place FS | `guttman` (Clear-level overwrite) | ATA Secure Erase (`hdparm --security-erase`) → Purge | Purge, else Destroy |
| SATA SSD | Not possible by overwrite | ATA Secure Erase / `blkdiscard -s` → Purge, if the drive supports and implements it correctly | Purge, else Destroy |
| NVMe SSD | Not possible by overwrite | `nvme sanitize` (crypto or block erase) → Purge | Purge, else Destroy |
| Any, **LUKS-encrypted from day one** | Not needed per file | Cryptographic erase: `cryptsetup luksErase` after making sure no key/header copies exist → Purge | same |
| btrfs / ZFS on anything | Not possible by overwrite | Device-level methods above (and delete snapshots) | as above |
| USB flash / SD | Not possible by overwrite | Often no sanitize command; treat as Destroy | Destroy |
| Network / FUSE | Not under local control | Ask the storage owner | n/a |

`guttman advise PATH|DEVICE` detects the case and prints the matching commands.
It never runs them.

## Why a read-back check is not proof

`--readback` fsyncs, drops the page cache, reads the file back and compares a
BLAKE2b digest. It detects I/O errors and silent corruption. It reads the
**logical** address; a remapping layer can answer correctly from a new location
while the old copy remains. The JSON report says so in its `note` field.

## Known limitations

- File names: guttman renames to random names (3 rounds) before unlinking, but
  journals, directory-entry slack and filesystem logs can retain old names.
- Sparse files: only allocated extents are overwritten; holes hold no data.
  If the filesystem cannot report extents, the whole file is written.
- `O_DIRECT` is used for aligned I/O only and falls back to `O_SYNC` (with a note)
  where unsupported; it does not change the device-level limits above.
- Recursive mode checks the storage of the top-level target only; a different
  filesystem mounted inside the tree is not re-checked.
- Interrupted runs leave indeterminate content; do not treat as deleted.
- Power loss mid-pass leaves partial overwrites.
- Not evaluated against any certification scheme.

## References

- NIST SP 800-88 Rev. 2, *Guidelines for Media Sanitization* (September 2025): <https://csrc.nist.gov/pubs/sp/800/88/r2/final>
- P. Gutmann, *Secure Deletion of Data from Magnetic and Solid-State Memory*, USENIX Security 1996, including the later epilogue (SSDs need different techniques; bypass the FTL): <https://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html>
- M. Wei, L. Grupp, F. Spada, S. Swanson, *Reliably Erasing Data From Flash-Based Solid State Drives*, USENIX FAST '11: <https://www.usenix.org/legacy/event/fast11/tech/full_papers/Wei.pdf>
