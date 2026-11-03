# ADR-0001: Pure-standard-library Python CLI that fails closed

| Field | Value |
| :---- | :---- |
| Status | Accepted |
| Date | 2026-11-03 |
| Deciders | @DakodaStemen |

## Context

The tool overwrites files in place on Linux. It runs on machines where installing dependencies is undesirable, and it handles data that must not be destroyed by mistake or reported as destroyed when it was not. Overwriting does not work on SSDs or copy-on-write filesystems (see [THREAT_MODEL.md](../../THREAT_MODEL.md)).

## Decision

- Write it in Python 3.10+ using only the standard library at runtime (`pyproject.toml` lists no runtime dependencies).
- Package with setuptools; the console script is `guttman` (`guttman.cli:main`).
- Detect storage type and filesystem first (`guttman/detect.py`) and refuse with exit code 2 where overwriting cannot work, unless `--force-unsafe` is given.
- Test with pytest, including a btrfs loop-mount test for copy-on-write behavior; lint with ruff; publish through PyPI Trusted Publishing (no stored token).

## Alternatives considered

| Alternative | Why not chosen |
| :---- | :---- |
| Compiled language | A single readable Python package is easier to audit; speed is bound by disk I/O |
| Warn and continue on SSD or CoW | A shredder that reports success without destroying data is worse than one that refuses |
| Third-party dependencies | Larger audit surface for a security tool |

## Consequences

**Positive**

- `pip install` pulls nothing else; `make ci` reproduces CI.
- Refusals are the default, so unsafe use needs an explicit flag.

**Negative**

- Linux only; the loop-mount test needs root-capable tools and is skipped without them.
- Python 3.10 is the floor.
