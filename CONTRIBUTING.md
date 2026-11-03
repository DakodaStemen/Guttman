# Contributing

`main` stays stable. Work happens on branches and lands through a pull request. Run `make ci` before you push.

## Setup

Needs Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```sh
make setup   # .venv with the package, pytest, ruff, build and twine (safe to re-run)
make help    # list targets
```

## Branches and pull requests

| Prefix | Use |
| :---- | :---- |
| `feat/...` | New features |
| `fix/...` | Bug fixes |
| `docs/...` | Documentation |
| `chore/...` | Tooling and repository hygiene |
| `ci/...` | Workflow changes |
| `test/...` | Tests only |

- PR titles follow Conventional Commits, matching the prefix: `feat: add ...`, `fix: ...`.
- One purpose per PR. Fill in `.github/PULL_REQUEST_TEMPLATE.md`.
- Commit messages state what changed and why. Weak: `updated files`. Strong: `fix: refuse when the device cannot be identified instead of warning`.

## Running tests and lint

```sh
make lint    # ruff check (rules in pyproject.toml)
make test    # pytest; the btrfs loop-mount test skips without the needed tools
make build   # sdist + wheel, twine check
make ci      # lint + test + build
```

## Rules

- The storage policy is fail-closed. A change that lets a run proceed on SSD, copy-on-write or unidentified storage without `--force-unsafe` needs a test and a [THREAT_MODEL.md](THREAT_MODEL.md) update.
- Never report success when an overwrite or read-back check failed.
- Never test against real data. Use temporary files.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
