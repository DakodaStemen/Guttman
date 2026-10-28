#!/usr/bin/env bash
# Records-friendly demo. Works ONLY on a throwaway temp file it creates itself.
set -e
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
type_cmd() { printf '\033[1;32m$\033[0m '; for ((i=0;i<${#1};i++)); do printf '%s' "${1:i:1}"; sleep 0.03; done; echo; sleep 0.4; }
cd "$D"
type_cmd "head -c 64M /dev/urandom > secret.bin && ls -l secret.bin"
head -c 64M /dev/urandom > secret.bin && ls -l secret.bin; sleep 1
type_cmd "guttman --dry-run secret.bin"
guttman --dry-run secret.bin; sleep 1.5
type_cmd "guttman --verify --progress secret.bin"
guttman --verify --progress secret.bin; sleep 1
type_cmd "ls secret.bin"
ls secret.bin 2>&1 || true
sleep 2
