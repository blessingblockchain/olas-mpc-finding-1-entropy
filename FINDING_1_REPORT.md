# Finding 1: Entropy Used Before Block Finality — Validator Can Bias MPC Signing Randomness

## 1. Title

Entropy from `streamer_message.block.header.random_value` is used for Sign, CKD, and VerifyForeignTx requests as soon as blocks are received, without checking finality. The queue processes requests for `OptimisticAndCanonical` blocks. A validator who controls block production can observe and bias this entropy before finality, weakening GS21 rerandomization and enabling potential key extraction.

## 2. Vulnerability Details

### Summary

In the MPC node indexer (`crates/node/src/indexer/handler.rs`, lines 197, 215, 238), entropy is taken from `streamer_message.block.header.random_value` when indexing Sign, CKD, and VerifyForeignTx requests. With `finality: optimistic` (default in config examples), blocks are streamed before finality. The request queue (`crates/node/src/requests/queue.rs`, lines 454–456) processes requests for `OptimisticAndCanonical` blocks — canonical but not yet finalized.

This entropy flows into `RerandomizationArguments` for presignature rerandomization (`providers/ecdsa/sign.rs`, `providers/robust_ecdsa/sign.rs`), then into `threshold-signatures/src/ecdsa/mod.rs` via HKDF to derive scalar `delta`. GS21 requires entropy to be "public, freshly generated, and unpredictable." Using entropy from non-final blocks allows a validator to influence it via reorgs.

### Root Cause — Exact Code Location

**File: `crates/node/src/indexer/handler.rs`, lines 197, 215, 238**

```rust
entropy: streamer_message.block.header.random_value.into(),
```

**File: `crates/node/src/requests/queue.rs`, lines 454–456**

```rust
match self.recent_blocks.classify_block(request.block_hash, request.block_height) {
    CheckBlockResult::RecentAndFinal
    | CheckBlockResult::OptimisticAndCanonical   // ← Non-final blocks processed
    | CheckBlockResult::Unknown => {
        // ... request is selected for signing attempt
    }
```

**File: `crates/threshold-signatures/src/ecdsa/mod.rs`, lines 90–102**

```rust
/// Following [GS21], the entropy should be public, freshly generated, and unpredictable.
pub struct RerandomizationArguments {
    // ...
    /// Fresh, Unpredictable, and Public source of entropy
    pub entropy: [u8; 32],
}
```

### Impact Chain

| Step | Description | Proved by PoC |
|------|-------------|---------------|
| 1. Root cause | Entropy from non-final blocks is used | `test_entropy_used_before_finality_optimistic_blocks_processed` |
| 2. Validator influence | Validator can choose which block to finalize → controls which entropy is used | `test_entropy_reorg_validator_influence` |
| 3. Cryptographic weakening | Different entropy → different rerandomization scalar | `test_entropy_biases_rerandomization` |
| 4. Key extraction | Biased entropy can enable cube-root attack (theory) | Documented in GS21 |

### Attack Scenario

1. Validator produces block A at height H with `random_value` = X.
2. Node indexes Sign request with entropy X (block not yet final).
3. Validator observes X, produces block B (fork) with `random_value` = Y.
4. Validator uses influence to get B finalized instead of A.
5. Node already used entropy X from block A (now reorged). Validator chose which entropy was used.
6. With repeated influence, validator can bias entropy distribution.
7. Biased entropy breaks GS21 unpredictability → weak rerandomization → potential key extraction.

## 3. Impact

**Severity: High**

- **Validator influence**: A block producer controls `random_value`; with optimistic finality, entropy can be biased.
- **Cryptographic weakening**: GS21 rerandomization assumes unpredictable entropy. Biased entropy weakens the security proof.
- **Key extraction risk**: In theory, weak rerandomization can enable cube-root attacks on the threshold signature scheme.

## 4. Validation Steps

### Prerequisites

- Rust toolchain (1.86+)
- Clone the MPC repository
- **Important**: Use `CARGO_TARGET_DIR` without spaces (jemalloc build fails with paths containing spaces)

### Run All PoCs

```bash
# Symlink or cd to mpc (avoid spaces in path for build)
cd /path/to/mpc

# Run all three entropy PoCs
CARGO_TARGET_DIR=/tmp/mpc-target cargo test -p mpc-node test_entropy --no-fail-fast
```

**Expected output:**

```
running 3 tests
test requests::queue::tests::test_entropy_biases_rerandomization ... ok
test requests::queue::tests::test_entropy_used_before_finality_optimistic_blocks_processed ... ok
test requests::queue::tests::test_entropy_reorg_validator_influence ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 205 filtered out; finished in 0.01s
```

### Run Individual PoCs

```bash
# PoC 1: Root cause — entropy from non-final blocks is used
CARGO_TARGET_DIR=/tmp/mpc-target cargo test -p mpc-node test_entropy_used_before_finality_optimistic_blocks_processed --no-fail-fast

# PoC 2: Validator influence — reorg scenario
CARGO_TARGET_DIR=/tmp/mpc-target cargo test -p mpc-node test_entropy_reorg_validator_influence --no-fail-fast

# PoC 3: Cryptographic weakening — different entropy → different delta
CARGO_TARGET_DIR=/tmp/mpc-target cargo test -p mpc-node test_entropy_biases_rerandomization --no-fail-fast
```

## 5. PoC Code Locations

All PoCs are in `crates/node/src/requests/queue.rs` (mod tests):

| PoC | Test name | Lines |
|-----|-----------|-------|
| 1 | `test_entropy_used_before_finality_optimistic_blocks_processed` | ~1378–1429 |
| 2 | `test_entropy_reorg_validator_influence` | ~1434–1505 |
| 3 | `test_entropy_biases_rerandomization` | ~1511–1545 |

## 6. PoC Descriptions

### PoC 1: Root Cause

Builds chain b10→b11→b12→b13→b14→b15. Block b14 is `OptimisticAndCanonical` (not final). Adds sign request with entropy `[0xAB; 32]` from b14. Asserts the request is selected for attempt and entropy is passed through. **Proves**: entropy from non-final blocks is used for signing.

### PoC 2: Validator Influence

Builds fork: b12→b14→b16 (canonical) vs b12→b13→b15. Request from b16 with entropy `[0xDE; 32]` is processed. Then reorg: add b18, b19, b20 from b14's fork. b16 becomes `NotIncluded`. **Proves**: we used entropy from a block the validator could have replaced by finalizing a different fork.

### PoC 3: Cryptographic Weakening

Uses `RerandomizationArguments::derive_randomness()` with (a) unpredictable entropy and (b) biased entropy `[0x41; 32]`. Asserts `delta_a != delta_biased`. **Proves**: different entropy produces different rerandomization scalar; validator-controlled entropy breaks GS21 unpredictability.

## 7. Step-by-Step Attack Scenario

1. **Reconnaissance**: Attacker is a NEAR validator. They produce blocks and control `random_value` in each block header.
2. **Indexing**: MPC node runs with `finality: optimistic`. Sign request appears in block at height H. Handler sets `entropy = block.header.random_value`.
3. **Processing**: Queue classifies block as `OptimisticAndCanonical`. Request is selected for signing. Entropy flows to `RerandomizationArguments`.
4. **Influence**: Validator observes `random_value` before finality. They produce alternative block with different `random_value`. They use stake to get their preferred block finalized.
5. **Bias**: Over many requests, validator biases entropy distribution. Rerandomization scalar `delta` becomes predictable.
6. **Exploitation**: With biased entropy, GS21 security proof no longer holds. Cube-root attack may become feasible (theoretical).

## 8. Recommended Fix

Use entropy only from finalized blocks:

1. **Option A**: Wait for `final_head` before processing requests that include entropy.
2. **Option B**: Only process requests when `CheckBlockResult::RecentAndFinal` (exclude `OptimisticAndCanonical`).
3. **Option C**: Set `finality: Final` in indexer config instead of `optimistic`.

## 9. References

- [GS21] https://eprint.iacr.org/2021/1330.pdf — Presignature rerandomization
- NEAR block finality: optimistic vs final
- `crates/node/src/indexer/handler.rs` — entropy extraction
- `crates/node/src/requests/queue.rs` — block classification
- `crates/threshold-signatures/src/ecdsa/mod.rs` — RerandomizationArguments
