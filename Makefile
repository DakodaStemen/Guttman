# An inherited PYTHONPATH (for example another Python's site-packages) breaks uv and pytest.
unexport PYTHONPATH

.DEFAULT_GOAL := help
.PHONY: help setup lint test build ci clean

VENV := .venv
PY   := $(VENV)/bin/python

help:
	@echo "make setup   create .venv with the package, pytest, ruff, build and twine (idempotent)"
	@echo "make lint    ruff check"
	@echo "make test    pytest"
	@echo "make build   build sdist and wheel, then twine check"
	@echo "make ci      lint + test + build"
	@echo "make clean   remove build output and caches"

setup:
	@command -v uv >/dev/null || { echo "need uv on PATH" >&2; exit 1; }
	uv venv --allow-existing $(VENV)
	uv pip install --python $(PY) -e ".[test]" ruff build twine

lint:
	$(PY) -m ruff check .

test:
	$(PY) -m pytest -q -rs

build:
	rm -rf dist
	$(PY) -m build
	$(PY) -m twine check dist/*

ci: lint test build

clean:
	rm -rf dist build .pytest_cache .ruff_cache *.egg-info
