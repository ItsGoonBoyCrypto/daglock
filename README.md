# DagLock — LOCK_V1 covenant (Kaspa L1 vesting / team-locks)

Non-custodial token vesting on Kaspa L1. A lock is a **covenant** enforced by every node: it releases
tokens on a fixed schedule, and nobody (team, Dagger, us) can accelerate or divert it. See
[docs/LOCKS_SPEC.md](docs/LOCKS_SPEC.md) for the full design.

**Status:** Phase 0 (TN10) PASSED · Phase 1 audit gate strong pass · independently red-teamed (clean)
· real-interpreter + on-chain validated. External audit pending. **Beta — not on mainnet publicly.**

## Layout

| File | What |
|---|---|
| `src/lockv1.js` | The covenant builder — WASM (`buildLockRedeem`) + pure-JS (`buildLockRedeemJS`, byte-identical), creation-time validation, vesting math. **The audited core.** |
| `src/verify.js` | Badge verifier — `verifyLock` (structural match to the frozen skeleton), `evaluateBadge` (requires genesis value == TOTAL, F1), `describeLock` (human terms, F4), `fingerprint`, `badgeTier`. WASM-free. |
| `src/test_model.js` | 200k randomized-schedule property sweep + creation-validation envelope. |
| `src/test_verify.js` | 24,480-mutant verifier byte-flip + F1/F4 cases. |
| `src/lifecycle.js` | TN10 lifecycle runner (create/status/claim). |
| `src/adversarial.js`, `src/adversarial_matrix.js` | TN10 attack tests — over-claim + the 7-case matrix (all rejected). |
| `src/overfund_test.js` | TN10 proof that an over-funded lock is refused a badge (F1). |
| `src/mainnet_admin.js` | **Mainnet** owner CLI (real KAS, dry-run default, cap, two-step confirm). |
| `bot/daglock_test_bot.js` | **Mainnet** Telegram test bot (@DagLockerBot) — owner-gated, same safety. |
| `harness/lock_harness.rs` | Rust harness — runs LOCK_V1 through the **real rusty-kaspa `TxScriptEngine`** (boundary, adversarial, property sweep, 20k-iter differential fuzz). |
| `AUDIT.md` | Internal audit (op-by-op, value-conservation proof, red-team §7b, all findings). |
| `PUBLISH.md` | Public verification page + threat model + frozen template fingerprint. |
| `MAINNET_TEST_SPEC.md` | Owner runbook for the mainnet smoke test. |

Frozen template fingerprint: `c8e2b56863dfee8cfe50ad765b5dc448e44e052d3b86b0ceec0591d5611e33d9`

## Run the tests

```bash
# offline (pure JS, no deps, no network) — also runs in CI:
node src/test_model.js
node src/test_verify.js         # or: npm test

# real interpreter (needs the rusty-kaspa checkout + GNU toolchain on this Windows box):
cargo +stable-x86_64-pc-windows-gnu run --release --example lock_harness -p kaspa-txscript

# live TN10 (needs a funded testnet wallet in state.json — gitignored):
node src/lifecycle.js create && node src/lifecycle.js status
node src/adversarial_matrix.js create   # wait ~5 min, then:
node src/adversarial_matrix.js run
```

## Security notes

- Wallet state files (`state.json`, `mainnet_state.json`, `bot/bot_state.json`) hold **private keys**
  and are gitignored. Never commit them. `bot/.env` (the bot token) is gitignored too.
- Claims are always signed **SIGHASH_ALL** (F2). The badge only proves the script is a genuine
  LOCK_V1 + funded==TOTAL; consumers must still confirm their own key and terms via `describeLock`.
- `LOCK_V1` covers **KAS** locks. KCC-20 token locks (v1.5) are a separate, not-yet-built template.

## Next

Mainnet smoke (MAINNET_TEST_SPEC.md via the bot or CLI) → external audit → wire into Dagger (6
sidecar routes + `/lock` `/locks` `/claim` + scanner 🔒 badge + standalone claim CLI) → canary →
owner-gated beta → founders → public. See memory `dagger-locks-next-steps`.
