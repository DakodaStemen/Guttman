# Security policy

## Supported versions

Only the latest release on PyPI / `main` receives fixes.

## Reporting a vulnerability

Please report privately via GitHub: **Security → Report a vulnerability**
(<https://github.com/DakodaStemen/Guttman/security/advisories/new>).
Do not open a public issue for an undisclosed vulnerability.

Include the version (`guttman --version`), filesystem/device, and a
reproduction. Expect an acknowledgement; there is no guaranteed response time
(single-maintainer project).

## What counts as a vulnerability

- The tool deletes or overwrites a file other than the one named (e.g. symlink
  or path-handling bugs).
- The tool reports success when the overwrite or read-back check failed.
- The fail-closed storage policy is bypassed without `--force-unsafe`.
- Unsafe handling of the `--report` output file.

## What does not

Guttman is documented as **best-effort**. Data remaining after shredding on
SSD/NVMe, copy-on-write filesystems, snapshots, journals or backups is a known
and documented limitation, not a vulnerability. See [THREAT_MODEL.md](THREAT_MODEL.md).
