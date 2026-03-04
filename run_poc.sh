#!/usr/bin/env bash
# Run Finding 1 PoCs — requires MPC repo with entropy tests
set -e

MPC_PATH="${MPC_PATH:-../mpc}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/mpc-target}"

if [[ ! -d "$MPC_PATH" ]]; then
    echo "Error: MPC repo not found at $MPC_PATH"
    echo "Set MPC_PATH to your mpc clone, e.g.: export MPC_PATH=/path/to/mpc"
    exit 1
fi

if [[ "$MPC_PATH" == *" "* ]]; then
    echo "Error: MPC_PATH contains spaces. Use a path without spaces (jemalloc build fails)."
    exit 1
fi

echo "Running PoCs from $MPC_PATH (target: $TARGET_DIR)"
cd "$MPC_PATH"
CARGO_TARGET_DIR="$TARGET_DIR" cargo test -p mpc-node test_entropy --no-fail-fast
