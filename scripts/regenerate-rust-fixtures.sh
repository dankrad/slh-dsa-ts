#!/usr/bin/env bash
# Requires the unmodified reference as a sibling checkout named reference.
set -euo pipefail
cd "$(dirname "$0")/.."
expected=462724e2b5f8ffe63a2ce76c9b1ab07099c1807b
actual=$(git -C ../reference rev-parse HEAD)
if [[ "$actual" != "$expected" ]]; then
  printf 'Wrong reference commit: expected %s, got %s\n' "$expected" "$actual" >&2
  exit 1
fi
if [[ -n "$(git -C ../reference status --porcelain --untracked-files=no)" ]]; then
  printf 'Reference has tracked-file modifications; refusing to regenerate fixtures\n' >&2
  exit 1
fi
out=$(mktemp vectors/.rust-differential.XXXXXX)
trap 'rm -f "$out"' EXIT
cargo run --locked --release --manifest-path scripts/rust-fixtures/Cargo.toml > "$out"
mv "$out" vectors/rust-differential.json
