# DagLock (LOCK_V1) — Internal Security Audit (Phase 1, §9-D)

**Scope:** the LOCK_V1 covenant redeem script (KAS locks) as built by
`src/lockv1.js` / `examples/lock_harness.rs`, its off-chain schedule math, creation-time validation,
and the badge verifier (`src/verify.js`).
**Status:** internal audit — passing gates recorded in §6. **Not yet externally audited.** Mainnet
use gated on the remaining §7 items. Date: 2026-08-11.

---

## 1. Design recap (what is trusted)

State is the covenant UTXO's **own amount**. Every schedule parameter is an immutable constant
compiled into the redeem script, so the P2SH address is fixed for the lock's life. There is no
mutable datum, counter, or payload to corrupt.

Core invariant the script enforces on every spend while not fully vested:

> the covenant UTXO created by this spend (output at the lock input's own index) holds **≥ floor**,
> where `floor = total − vested(now)` and `now = tx.lock_time`.

Because `vested(now)` is monotonic non-decreasing and the covenant always retains ≥ `floor(now)`,
**cumulative amount removed from the covenant across any sequence of claims ≤ vested(now)**. This is
the whole safety story; §3 shows each opcode serves it.

---

## 2. Op-by-op annotation

Redeem (96 bytes for the reference 180-period lock; length varies with minimal-encoded constants):

```
<beneficiaryPub:32>  OpCheckSigVerify        ; (1) fail unless top-of-stack is a valid beneficiary sig
<cliffMs>            OpCheckLockTimeVerify    ; (2) require tx.lock_time >= cliffMs; pin Time-type;
                                             ;     reject if this input's sequence == u64::MAX
OpTxLockTime                                 ; push now (= tx.lock_time; a trusted lower bound on
                                             ;     real time — consensus rejects tx until median-time
                                             ;     passes lock_time)
<startMs> OpSub                              ; elapsed = now - startMs   (>=0: cliff>=start guarantees)
<periodMs> OpDiv                             ; k' = elapsed / periodMs   (periodMs>=60000, never 0)
<nPeriods> OpMin                             ; k  = min(k', nPeriods)    (cap so vested<=total)
<perPeriod> OpMul                            ; vested = k * perPeriod     (<= 2^62 by creation cap)
<total> OpSwap OpSub                         ; floor = total - vested     (>=0)
OpDup <0> OpGreaterThan OpIf                 ; if floor > 0:
  OpTxInputIndex OpTxOutputAmount            ;   push output[i].amount, i = own input index
    OpLessThanOrEqual OpVerify               ;   require floor <= output[i].amount
  OpTxInputIndex OpTxOutputSpk               ;   push output[i].spk
    OpTxInputIndex OpTxInputSpk OpEqualVerify;   require output[i].spk == own input spk  (recursion)
  OpTxInputIndex OpOutputCovenantId          ;   push output[i].covenantId
    OpTxInputIndex OpInputCovenantId         ;   push own input covenantId
    OpEqualVerify                            ;   require equal  (KIP-20 lineage continuity)
OpElse OpDrop OpEndIf                        ; else (fully vested): drop floor; no output constraints
OpTrue                                       ; success
```

### Why each guard is necessary and sufficient

- **(1) Sig first.** Every spend path requires the beneficiary signature, so no third party can
  claim or grief (dust-spam) the covenant. The signature also binds the whole tx (SIGHASH_ALL), so
  the claimer cannot have outputs rewritten by a relayer.
- **(2) CLTV.** Three jobs in one opcode (verified against rusty-kaspa
  `opcodes/mod.rs::OpCheckLockTimeVerify` and `tx_validation_in_header_context.rs`):
  (a) enforces the cliff (`lock_time >= cliffMs`);
  (b) since `cliffMs >= 5e11 = LOCK_TIME_THRESHOLD`, forces `tx.lock_time` into the **Time** domain,
  so a DAA-score value cannot be substituted to distort the vesting arithmetic;
  (c) rejects the input if its `sequence == u64::MAX`, closing the "finalize all inputs to skip
  lock_time checks" bypass. Consensus separately guarantees `tx.lock_time < past-median-time`, so
  `now` cannot be pushed into the future to over-vest.
- **elapsed / k / vested.** `startMs <= cliffMs <= now` ⇒ `elapsed >= 0`. `periodMs >= 60000` ⇒ no
  `OpDiv` by zero. `OpMin` caps `k <= nPeriods` ⇒ `vested <= total`. Creation cap
  `perPeriod*nPeriods <= 2^62` ⇒ `k*perPeriod` cannot overflow i64.
- **floor branch.** `OpTxOutputAmount` / `OpTxOutputSpk` / `OpOutputCovenantId` are bounds-checked
  in consensus: if the tx has ≤ i outputs they **fail closed** (script error ⇒ tx rejected), so a
  claimer cannot dodge the continuation constraint by omitting the output. The three checks force
  output[i] to be a genuine continuation of *this* covenant holding ≥ floor.
- **Own-index binding.** All output introspection uses `OpTxInputIndex`, so each lock input
  constrains the output at *its own* index. In a multi-lock tx, input j constrains output j
  independently; a single output cannot satisfy two different lock inputs (§4).
- **Fully-vested branch.** When `floor == 0` there is nothing left to protect; the beneficiary
  (already authenticated) sweeps everything, including rounding dust. No continuation required, so
  the covenant terminates cleanly (verified on-chain: final claim left 0 UTXOs).

---

## 3. Value-conservation argument (no early extraction)

Let `L` be the covenant UTXO amount before a claim at time `t`. The script requires the new
covenant output to hold `≥ floor(t) = total − vested(t)`. Thus the amount leaving the covenant in
this claim `≤ L − floor(t)`. By induction, starting from `L₀ = total`, after any sequence of claims
at times `t₁ ≤ t₂ ≤ …`, the covenant retains `≥ floor(tₙ)` and cumulative removed `≤ total −
floor(tₙ) = vested(tₙ)`. Funding inputs the claimer adds for fees do not change this: the covenant
output’s **value floor** is absolute, independent of which input funds it (UTXO value is fungible).
∴ **no claimer can extract more than has vested**, and a fully-honest claimer can always extract
exactly `vested`. Confirmed on live TN10 (partial + adversarial + final).

---

## 4. Multi-input / index-confusion analysis

- Two lock UTXOs A (input 0) and B (input 1) in one tx: A's script constrains output[0]; B's
  constrains output[1]. Distinct indices ⇒ no shared output. If A and B are different covenants
  (different covid and/or spk), the lineage/recursion checks further prevent cross-satisfaction.
- Shards of the same logical lock are separate covenants with **distinct covenant IDs**, so each
  shard's `OpOutputCovenantId == OpInputCovenantId` check pins its own continuation. Confirmed by
  reasoning + the covenant-id lineage test.
- Placing a lock input at index i with fewer than i+1 outputs: `OpTxOutputAmount(i)` fails closed.
- The beneficiary payout and change are unconstrained extra outputs; the signature (SIGHASH_ALL)
  commits to them, so only the beneficiary chooses them and no relayer can rewrite them.

**Residual note (defense-in-depth, not a break):** the covenant-id lineage check overlaps with
consensus `CovenantsContext::from_tx` validation. Keeping the in-script check is intentional — it
pins the continuation to *this input's* id specifically, not merely to *a* valid binding.

---

## 5. Bugs found and fixed during Phase 0/1

1. **SDK signature double-wrap (funding path).** Vendored kaspa WASM 2.0.1 `createInputSignature`
   returns the *complete pushed* sig element; the KRON SDK's `signFundingInputs` wraps it again →
   node rejects "malformed signature". Fixed in the harness by assigning the sig directly; flagged
   for the live KRON service (separate task). Evidence: `src/lifecycle.js::signFunding`.
2. **Verifier tokenizer DoS.** `OpPushData4` length assembled with `<< 24` wrapped negative in JS
   32-bit signed math → cursor moved backwards → infinite token append → OOM. A malicious script
   could DoS the badge verifier. Fixed: length via multiplication + overrun bounds-check + hard
   token-count backstop. Evidence: `src/verify.js::tokenize`, regression-covered by the 24,480-mutant
   byte-flip sweep.
3. **Median-time lag (operational).** TN10 past-median-time lags wall-clock ~130s; claims must
   anchor `tx.lock_time` to `getBlockDagInfo().pastMedianTime` (minus margin), not `Date.now()`,
   or consensus rejects "not finalized." Encoded in `src/lifecycle.js`.

---

## 6. Test evidence (what passed)

- **On-chain (live TN10, real consensus — the authoritative interpreter):** create → partial claim
  (continuation held floor under the same covid) → **adversarial over-claim REJECTED** ("script ran
  but verification failed") → final claim (swept remainder, covenant terminated, 0 UTXOs).
- **On-chain adversarial matrix (`adversarial_matrix.js`, live TN10):** a battery fired at one live
  lock UTXO — **all 7 attacks REJECTED, honest control ACCEPTED**: over-claim (underfund
  continuation), wrong continuation spk, missing continuation, third-party signature, wrong covid on
  continuation, continuation at wrong output index, `lock_time < cliff` (CLTV). Empirically confirms
  every discrete negative case the red-team/audit reasoned about, against the real interpreter.
- **F1 over-funding (`overfund_test.js`, live TN10):** an over-funded lock (8 vs 5 KAS TOTAL) is
  correctly refused a badge by `evaluateBadge`.
- **Model / creation-validation (`test_model.js`):** 200,000 randomized valid schedules — vested
  bounded [0,total], monotonic floor, `vested == k*perPeriod`, no i64 overflow at caps; full accept/
  reject envelope for §3.4; single-period and cliff==start boundaries.
- **Verifier (`test_verify.js`):** real lock verifies + round-trips; **24,480 single-byte mutants,
  0 skeleton-breaks** (every still-verifying mutant only changed a constant slot); truncate/extend/
  non-lock rejected; total-inconsistency splice rejected; badge tiers.
- **Pure-JS builder == WASM builder** byte-for-byte across small-int and near-cap params.
- **Rust harness (`examples/lock_harness.rs`) — RUN, real `TxScriptEngine`:** **19/19 checks pass**
  over boundary + adversarial + a property sweep across the whole vest window (exact-floor accept &
  underpay-by-1 reject) + a **20,000-iteration randomized differential fuzz** (random schedules:
  honest claim accepted, single injected fault rejected) + a **multi-lock/multi-input** suite (two
  distinct locks in one tx: honest → both inputs accept and each binds its own output index; swapped
  continuations → rejected; shared single continuation → rejected — no cross-satisfaction, closing
  the red-team's subtlest concern empirically). Each rejection returns the precise consensus error:
  `UnsatisfiedLockTime` (pre-cliff, lock_time<cliff), `VerifyError` (underfund/drain/wrong-spk/
  third-party-sig), `WrongGenesisCovenantId` (wrong covid, caught at covenant-context build),
  `InvalidSigHashType` (garbage sig). Built + run locally via the **GNU host toolchain**
  (`cargo +stable-x86_64-pc-windows-gnu run --release --example lock_harness -p kaspa-txscript`, with
  the mingw-w64 bin on PATH); the MSVC target still can't link here (no Windows SDK).

---

## 7. Remaining before mainnet (open)

- [x] Expand the **on-chain** adversarial matrix beyond over-claim — DONE (`adversarial_matrix.js`):
      7 attacks rejected + honest control accepted on live TN10 (§6).
- [x] Run `lock_harness` (exhaustive real-interpreter timing/property sweep) — DONE locally via the
      GNU host toolchain, 15/15 pass (§6). Wire into CI for regression + archival.
- [ ] KCC-20 token-lock path (v1.5) — separate covenant + owner-transfer semantics; not covered here.
- [ ] Independent external review before KCC-20 or > $100k TVL (Sherlock precedent in-ecosystem).
- [ ] Publish template fingerprint(s) + this threat model on the website; freeze the audited bytecode.
- [ ] Fresh-session red-team sign-off (in progress) folded in.

---

## 7b. Independent red-team (2026-08-11)

A fresh-session adversarial review traced the script against the vendored rusty-kaspa consensus
source (opcode semantics, `check_tx_is_finalized`, covenant-id validation, clean-stack rule).
**Verdict: no fund-theft, over-claim, permanent-lock, or lock_time over-vesting for a correctly
created lock.** Confirmed the value-conservation argument (§3), the finalization×CLTV-sequence
interlock capping `lock_time` at past-median-time (§2), fail-closed OOB introspection, and that
CLTV pops its argument (clean stack). Findings were product-integrity/footgun, not on-chain breaks:

- **F1 [Medium] — funded amount not bound on-chain (FIXED in verifier).** Script protects
  `TOTAL = nPeriods*perPeriod` (a constant), never its own UTXO balance. If a lock is funded with
  `B > TOTAL`, the excess `B − TOTAL` is immediately liquid/unvested; the badge could misrepresent
  locked value. Fix: creation asserts genesis `value == TOTAL`; the badge verifier now takes the
  on-chain genesis value + current amount and **refuses/flags any lock where genesis value != TOTAL**
  (see `verify.js::evaluateBadge`, tested by an over-funded TN10 case).
- **F2 [Low] — SIGHASH_ALL footgun (ADDRESSED).** Covenant can't constrain sighash type; a
  beneficiary induced to sign SINGLE/NONE could have payout outputs rewritten. The claim signer pins
  `SighashType.All` behind a named constant with a hard-requirement comment
  (`lifecycle.js::CLAIM_SIGHASH`); any production signer MUST do the same and never expose another
  type.
- **F3 [Low] — beneficiary self-sharding over-locks (freezes, never over-withdraws) (DOCUMENTED).**
  `floor` is schedule-**total**-based (deliberate: keeps the P2SH address static), so a beneficiary
  who splits a lock into covid-lineage shards each smaller than `floor` makes them temporarily
  unspendable until vesting advances enough that `floor ≤ shard amount` (all sweep at full vest).
  Strictly conservative — no path yields cumulative withdrawal > `vested(t)` — and only a beneficiary
  crafting non-standard claims (never the standard tooling) can reach it. Acceptable; noted in spec.
- **F4 [Info] — creation guards off-chain only (ADDRESSED).** `validateParams` is not on-chain; a
  malicious creator can hand-build a bad redeem (e.g. periodMs=0 → unspendable, wrong pubkey). The
  verifier now renders `describeLock(params)` — beneficiary pubkey, human dates, per-period release,
  duration, and an explicit confirm-prompt — so any consumer confirms their own key + the advertised
  terms from the verified script. The badge proves the script IS a genuine LOCK_V1; it is not a
  correctness proof of creator intent, and the UI must present `describeLock` alongside it.
- **F5 [Info] — median-time drift (NO ACTION).** `vested` derives from `lock_time` capped at
  past-median-time; miner nudge is sub-minute, immaterial for multi-month schedules. Inherent to
  time-based locks.

## 8. Reproduce

```bash
cd dagger/locks-covenant
node src/test_model.js      # 200k schedule property sweep + creation validation
node src/test_verify.js     # 24,480-mutant verifier byte-flip
# live TN10 lifecycle (needs a funded TN10 wallet in state.json):
node src/lifecycle.js create && node src/lifecycle.js status
node src/lifecycle.js claim              # partial, then (after full vest) final
node src/adversarial.js                  # over-claim must be REJECTED
node src/adversarial_matrix.js create    # then wait ~5 min (cliff must mature in median-time)
node src/adversarial_matrix.js run       # 7 attacks REJECTED + honest control ACCEPTED
node src/overfund_test.js                # over-funded lock must be refused a badge (F1)
# real-interpreter harness — GNU host toolchain (runs on this Windows box; also CI):
cargo +stable-x86_64-pc-windows-gnu run --release --example lock_harness -p kaspa-txscript
```
