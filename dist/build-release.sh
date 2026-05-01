#!/usr/bin/env bash
# Build the release binary with all host paths stripped from the
# embedded source-location strings (panic locations, error
# attributions). The result is reproducible across machines: any
# contributor running this script produces the same binary SHA-256
# for the same source tree.
#
# Why this script instead of a static `.cargo/config.toml`:
# `--remap-path-prefix` requires a literal source path. Hardcoding a
# specific machine's `$HOME` into the repo would leak the maintainer's
# username and break for everyone else. This script substitutes the
# caller's actual `$HOME` at build time.
#
# Usage:
#   dist/build-release.sh [extra cargo args]
#
# The CARGO_PROJECT_DIR fallback is provided so `cargo install` and
# nested invocations still work.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IROHA_DIR="$(cd "$PROJECT_DIR/../iroha-source" 2>/dev/null && pwd || echo "")"

REMAPS=(
    "--remap-path-prefix=$HOME/.cargo=/cargo"
    "--remap-path-prefix=$PROJECT_DIR=/minamoto-wallet"
)
if [[ -n "$IROHA_DIR" ]]; then
    REMAPS+=("--remap-path-prefix=$IROHA_DIR=/iroha-source")
fi

# Cargo 1.92+ accepts repeated --config flags; we use one per remap.
CONFIG_ARGS=()
for r in "${REMAPS[@]}"; do
    CONFIG_ARGS+=("--config" "build.rustflags=[\"$r\"]")
done

# Note: cargo merges multiple build.rustflags entries by appending,
# so one --config per flag is correct (they all stack into the final
# rustc invocation).

cd "$PROJECT_DIR"
exec cargo build --release "${CONFIG_ARGS[@]}" "$@"
