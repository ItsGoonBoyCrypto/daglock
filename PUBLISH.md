# DagLock — Public Verification & Threat Model (LOCK_V1)

DagLock is non-custodial token vesting on Kaspa L1. A lock is a **covenant** — a script enforced by
every Kaspa node — that releases tokens on a fixed schedule. Once created, **nobody** (not the team,
not Dagger, not the DagLock authors) can accelerate, divert, or unlock it early. This page lets
anyone verify a lock independently, without trusting Dagger.

## Frozen template — LOCK_V1

- **Template fingerprint (stable across every lock):**
  `c8e2b56863dfee8cfe50ad765b5dc448e44e052d3b86b0ceec0591d5611e33d9`
  This is a hash of the script's fixed opcode skeleton with the schedule constants zeroed out, so it
  is identical for every DagLock regardless of amount, dates, or beneficiary.
- **What varies per lock (the only freedom):** beneficiary public key, start, cliff, period length,
  number of periods, and the amount released per period. Everything else — the logic — is fixed and
  audited.
- **Audited builder:** `src/lockv1.js` (`buildLockRedeem` / `buildLockRedeemJS`, byte-identical).
- **Redeem size:** ~91–98 bytes (varies only because numeric constants are minimally encoded).

## What the covenant guarantees (enforced by consensus)

1. **Only the beneficiary can claim.** Every spend requires the beneficiary's signature.
2. **Nothing before the cliff.** Enforced by `OpCheckLockTimeVerify` against the tx's median-time.
3. **No early extraction, ever.** At all times the covenant retains at least
   `floor = TOTAL − vested(now)`, so the cumulative amount claimed can never exceed what has vested.
   `TOTAL = periods × perPeriod`. (Proven by construction, by 200k model cases, by the real
   rusty-kaspa interpreter, and on live testnet — including rejected theft attempts.)
4. **The remainder stays locked.** Each partial claim must return the unvested balance into the
   identical covenant (same script, same on-chain covenant-id lineage).
5. **It ends cleanly.** Once fully vested, the beneficiary sweeps the remainder; the covenant closes.

## How to verify a lock yourself

1. Fetch the lock's redeem script from the covenant (via KasCov / a Kaspa node).
2. Run `verifyLock(redeem)` (`src/verify.js`) — it confirms the script's opcode skeleton **exactly**
   matches the fingerprint above (one wrong byte → no match) and extracts the schedule.
3. Confirm the funded amount: the badge is only valid if the lock's **genesis value equals TOTAL**
   (`evaluateBadge`). An over-funded lock is refused, because any excess over TOTAL would be liquid.
4. Confirm the terms with `describeLock(params)` — check the **beneficiary key is the intended one**
   and the dates/amounts match what was advertised.

## Honest limitations (what a badge does NOT prove)

- **It proves the script is a genuine LOCK_V1 and the funded amount matches the schedule.** It does
  **not** prove the creator's intent — always confirm the beneficiary key and terms yourself (step 4).
- Locks are **time-based** on median block-time; sub-minute miner drift is possible and immaterial
  for real (multi-month) schedules.
- **Claims must be signed SIGHASH_ALL** (DagLock tooling enforces this). Never sign a DagLock claim
  with any other sighash type.
- LOCK_V1 covers **KAS** locks. KCC-20 token locks (v1.5) are a separate template, not covered here.

## Status

Internally audited + independently red-teamed (no fund-theft, over-claim, permanent-lock, or
lock_time over-vesting found for a correctly created lock). Validated against the real rusty-kaspa
script interpreter and on live testnet. **External third-party audit is pending** — until then,
treat DagLock as beta and verify every lock yourself using the steps above.
