# MPC Finding 1: Entropy Used Before Block Finality

Security audit finding and PoC for the OLAS MPC node — entropy from non-final blocks is used for signing, enabling validator influence and cryptographic weakening.

## Finding Summary

| Field | Value |
|-------|-------|
| **Title** | Entropy Used Before Block Finality |
| **Severity** | High |
| **Component** | MPC Node (indexer, queue, threshold-signatures) |
| **Root Cause** | `handler.rs` uses `block.header.random_value` before finality; queue processes `OptimisticAndCanonical` blocks |

## Impact Chain (with PoCs)

| Step | Impact | PoC |
|------|--------|-----|
| 1 | Entropy from non-final blocks is used | `test_entropy_used_before_finality_optimistic_blocks_processed` |
| 2 | Validator can influence which entropy is used (reorg) | `test_entropy_reorg_validator_influence` |
| 3 | Biased entropy → different rerandomization scalar | `test_entropy_biases_rerandomization` |

## Run the PoCs

**Prerequisites:** MPC repo cloned, Rust 1.86+, `CARGO_TARGET_DIR` without spaces (e.g. `/tmp/mpc-target`).

```bash
cd /path/to/mpc
CARGO_TARGET_DIR=/tmp/mpc-target cargo test -p mpc-node test_entropy --no-fail-fast
```

Expected: 3 tests passed.

## Contents

- `FINDING_1_REPORT.md` — Full report with root cause, impact, **complete PoC code**, setup, and fix
- `README.md` — This file

## Setup

1. Clone the MPC repo (or use one with PoCs).
2. Add the 3 PoC tests from `FINDING_1_REPORT.md` §5 to `crates/node/src/requests/queue.rs` (mod tests).
3. Run: `CARGO_TARGET_DIR=/tmp/mpc-target cargo test -p mpc-node test_entropy --no-fail-fast`
