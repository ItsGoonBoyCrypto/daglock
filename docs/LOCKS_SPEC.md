# DagLock — Streaming / Vesting / Team-Lock Covenants on Kaspa L1

**Product name: DagLock** (formerly "Dagger Locks"). Kaspa L1 covenant-based vesting/team-locks,
surfaced through Dagger.


**Status:** SPEC — not built. Nothing ships until every item in §9 (audit & test gates) is green.
**Product family:** "Dagger Locks" (team locks + vesting) now; "Dagger Streams" (payroll/grants) phase 2; subscriptions phase 3.
**Author:** spec drafted 2026-08-11 from the covenant-plays research sweep (see memory: covenant-plays-research).

---

## 1. What it is

A non-custodial covenant that holds KAS (v1) or KCC-20 tokens (v1.5) and releases them to a
beneficiary on a schedule enforced by Kaspa consensus — not by Dagger, not by an indexer, not by
a multisig. Anything not yet vested is *forced by script* to return into the same covenant.
Once created, nobody — not the team, not Dagger, not us — can accelerate it.

**The wedge:** rug-proof team locks for launches. Every KRON / LFG launch can advertise
"team allocation provably vesting on-chain," and Dagger + Scanner cards show a verified 🔒 badge
with a KasCov (covenants.kaspa.com) deep link. Nobody on Kaspa has this. Sablier/Team Finance
proved the demand on EVM chains; Kaspa's 10bps + covenant IDs make it native here.

**Products in the family (one covenant template, different parameters):**

| Product | Cliff | Linear vest | Cancelable | Target user |
|---|---|---|---|---|
| Team lock | yes | yes | **never** (immutability IS the product) | launchpad teams |
| Vesting grant | optional | yes | dual-sig (payer+beneficiary) optional path | contributors, advisors |
| Stream (phase 2) | no | continuous | payer-cancel with vested-to-date guaranteed | payroll, grants |

---

## 2. Consensus primitives used (all Active on mainnet since Toccata, 2026-06-30)

- **KIP-10 / KIP-17 introspection:** `OpTxInputSpk`, `OpTxOutputSpk`, `OpTxOutputAmount`,
  `OpTxInputAmount`, `OpTxOutputCount`, plus locktime introspection (KIP-17 extends
  introspection to all tx fields including lock_time).
- **KIP-17 arithmetic:** 8-byte signed ints, `OpMul`, `OpDiv`, `OpMod`.
- **KIP-20 covenant IDs:** consensus-tracked lineage. Lock creation = *genesis* binding;
  every partial claim recreates the covenant via *continuation* binding, so the lock's
  covenant_id is stable for its whole life → KasCov shows one continuous lineage, and the
  Scanner badge can key on covenant_id alone.
- **KIP-9 storage mass:** relevant to claim-cadence guidance and anti-dust-griefing (§6).
- **Time source:** transaction `lock_time` (unix-ms form). Consensus only accepts a tx whose
  lock_time has passed, so the script can read the tx's own lock_time as a *trusted lower
  bound on current time* — the standard CLTV pattern, done via introspection.
  ⚠ **Phase-0 validation item:** confirm on TN10 (a) exact lock_time acceptance semantics in
  rusty-kaspa v2.0.1+ (threshold between DAA-score and unix-ms interpretation, and any
  input-sequence finality requirement for lock_time to be enforced), (b) that lock_time
  introspection returns the raw u64 we expect. **Do not build past Phase 0 until confirmed.**

**Explicitly NOT used:** Silverscript for production bytecode (experimental, pre-v1, testnet-only
per its own README). We hand-write the script (~30–40 ops) or use a *pinned* Silverscript build
strictly as a codegen aid, then review and freeze the **raw bytecode** as the audited artifact.
The audited template hash is the root of trust for the whole product (§7).

---

## 3. Covenant design

### 3.1 State model — amount IS the state

The elegant trick: the only mutating state is *how much is left*, and that is the covenant
UTXO's own amount. Everything else is a compile-time constant baked into the redeem script.

> **Audit notes (red-team 2026-08-11):**
> - **Floor is schedule-TOTAL-based, not per-UTXO** (F3). The continuation floor is `TOTAL − vested`
>   where `TOTAL = N_PERIODS × PER_PERIOD` is a constant; the script never reads its own balance
>   (this keeps the P2SH address static). Consequence: the genesis funded value MUST equal `TOTAL`
>   (F1) — enforced at creation and required by the badge verifier (`evaluateBadge` refuses any lock
>   whose on-chain genesis value ≠ TOTAL, since excess would be immediately liquid). A beneficiary
>   who self-shards into pieces smaller than the floor only *freezes* those pieces until vesting
>   catches up — strictly conservative, never over-withdraws.
> - **Claims MUST be signed SIGHASH_ALL** (F2) — the covenant can't constrain the sighash type, and
>   SINGLE/NONE would leave payout outputs rewritable. Pinned in the signer.
> - **The badge proves the script is a genuine LOCK_V1, not the creator's honesty** (F4). The UI must
>   show `describeLock()` (beneficiary pubkey + human dates + amounts) so the consumer confirms their
>   own key and the advertised terms; off-chain creation guards can't bind a hand-built redeem.

```
Constants (baked at creation, immutable):
  BENEFICIARY_SPK   script pubkey of the claimer (their wallet)
  BENEFICIARY_PUB   pubkey for the claim-path signature
  START_MS          vest start (unix ms)
  CLIFF_MS          absolute cliff time (unix ms); = START_MS if no cliff
  PERIOD_MS         claim granularity, e.g. 86_400_000 (1 day)
  N_PERIODS         total number of periods (u16-scale, capped — see §3.4)
  PER_PERIOD        amount released per period (sompi / token base units)
  TOTAL             = N_PERIODS × PER_PERIOD (creation-time invariant)
  [CANCEL_PUB_A/B]  only in the cancelable variant — absent from team locks
```

Derived at spend time inside the script:
```
now        = tx.lock_time                      // trusted lower bound (§2)
elapsed    = now - START_MS
k          = min(elapsed / PERIOD_MS, N_PERIODS)   // periods fully elapsed
vested     = k × PER_PERIOD
remaining  = this_input.amount                     // introspected
released   = TOTAL - remaining
claimable  = vested - released
```

No datum, no payload state, no counter to corrupt. `released` can never be wrong because it is
literally the ledger.

### 3.2 Spend paths

**Path A — partial claim** (before fully vested):
```
require signature(BENEFICIARY_PUB)                 // anti-griefing, §6.3
require now >= CLIFF_MS
require tx.output_count >= 2
require tx.output[0].spk    == this_input.spk      // RECURSION: remainder back into same covenant
require tx.output[0].amount >= remaining - claimable
require tx.output[1].spk    == BENEFICIARY_SPK
// output[1] amount not constrained — output[0] floor already caps what can leave.
// (Beneficiary can claim less than max; extra just stays locked. Fee comes from an
// extra input the claimer adds — the covenant amount equation never funds fees.)
```
Continuation binding on output[0] carries the covenant_id forward (KIP-20).

**Path B — final claim** (fully vested):
```
require signature(BENEFICIARY_PUB)
require now >= START_MS + N_PERIODS × PERIOD_MS
// no continuation output required — covenant terminates, everything spendable to anywhere
// the beneficiary signs for (sweeps rounding dust too)
```

**Path C — cancel (grants/streams variant ONLY, compiled out of team locks):**
```
require signature(CANCEL_PUB_A) AND signature(CANCEL_PUB_B)   // payer + beneficiary
require tx.output[0].spk == BENEFICIARY_SPK
require tx.output[0].amount >= vested - released               // vested-to-date is untouchable
// remainder returns to payer (output[1].spk == PAYER_SPK)
```
The team-lock template **must not contain** Path C — its absence is what the verifier badge
certifies. Two audited template hashes: `LOCK_V1` (paths A+B) and `GRANT_V1` (A+B+C).

### 3.3 Why per-period instead of continuous `total × elapsed / duration`

Naive muldiv overflows: amounts are 8-byte ints, elapsed is ~3.2e10 ms/yr, and
`TOTAL × elapsed` blows past 2^63 for any real token supply. Per-period math bounds it:

- `k ≤ N_PERIODS` and we cap `N_PERIODS ≤ 10_000` at creation (27 years daily, or ~7 days
  at 1-minute granularity for streams).
- Creation-time validation requires `PER_PERIOD ≤ (2^62) / N_PERIODS`, so `k × PER_PERIOD`
  provably cannot overflow.
- **Big-supply tokens** (e.g. 1e12 supply × 1e8 decimals) can exceed the cap → the sidecar
  **shards** the lock into M parallel covenants of TOTAL/M each, identical schedules. Badge
  aggregates across shards (they share creation tx + are enumerated in the lock registry §5.4).
  Sharding also parallelizes claims (UTXO model bonus).

### 3.4 Creation-time validation (sidecar-enforced before signing)

- `TOTAL == N_PERIODS × PER_PERIOD` exactly (no rounding surprises)
- `START_MS ≥ now - 24h` (no backdated "already 90% vested" gaming of the badge)
- `CLIFF_MS ∈ [START_MS, START_MS + N_PERIODS × PERIOD_MS]`
- `PERIOD_MS ≥ 60_000` (floor keeps claim spam and storage mass sane)
- overflow cap from §3.3; beneficiary address checksum-validated on the right network
- **Double-confirm UX with parameter echo** — funds are consensus-locked; a wrong beneficiary
  key means the tokens vest to the wrong party *forever*. Show human dates, amounts, and an
  irreversibility warning; require typed confirmation (same pattern as Dagger withdraw flow).

### 3.5 Asset support

- **v1 — KAS locks.** Simplest covenant; immediately useful (team KAS treasuries, LP-proceeds
  locks, KAS grants) and proves the whole pipeline end-to-end.
- **v1.5 — KCC-20 locks** (the actual wedge — teams lock *their token*). KCC-20 ownership is
  covenant-lineage-based and an owner can be **another covenant** (per the KCC-20 convention),
  which is exactly what we need: the token covenant's owner = our lock covenant.
  ⚠ **Phase-0 validation items:** (a) exact KCC-20 owner-transfer semantics and how a
  covenant-owner authorizes a transfer (co-spend of lock covenant + token covenant in one tx);
  (b) **what standard KRON / LFG launchpad tokens actually use today** — inspect via KasCov and
  the sidecar `/token-meta` route. If launches are still legacy KRC-20 (indexer-based), a
  trustless vest is NOT possible for them (indexer state ≠ consensus state) — at most a
  time-locked address, which we will NOT badge as "locked ✅" (would dilute the badge's meaning).
  In that case v1.5 waits for the KCC-20/native-KRC-20 migration and we say so publicly —
  honesty is the moat.

---

## 4. Trust & threat model

**Non-custodial by construction.** Dagger builds and broadcasts the creation tx, but after
confirmation the schedule is enforced by every Kaspa node. Dagger disappearing does not strand
funds: the covenant is standard script; we publish an open-source standalone claim CLI (§5.5)
so beneficiaries never depend on our infra.

| Threat | Mitigation |
|---|---|
| Malicious/buggy template (theft path hidden in script) | Single audited bytecode template per version; badge verifier compares on-chain redeem script against the frozen template hash byte-for-byte, only constants may differ (§7) |
| Team backdates START_MS to appear mostly-vested | Creation-time rule §3.4 + verifier recomputes schedule from constants and displays real dates; badge shows "X% unlocked, ends YYYY-MM-DD" not just a checkmark |
| Team locks 1% of supply, advertises "locked" | Badge always shows **% of total supply** locked (verifier reads token supply via sidecar); tiered badge: 🔒 ≥20% supply ≥6mo, 🔓 partial, ⚠ trivial |
| Griefer force-claims tiny amounts to dust the beneficiary | Claim paths require beneficiary signature (§3.2); KIP-9 storage mass additionally prices dust outputs |
| lock_time gaming (claim earlier than real time) | Consensus rejects txs whose lock_time hasn't passed — miner drift is bounded; PERIOD_MS ≥ 60s makes sub-minute drift irrelevant |
| Overflow / rounding theft | §3.3 caps proven at creation; property-tested + fuzzed (§9); Path B sweeps residual dust |
| Wrong beneficiary key at creation | §3.4 double-confirm; optional dry-run on TN10 first for large locks |
| Fee-source confusion (claim fee eaten from locked funds) | Amount equation constrains output[0] floor; fees must come from claimer's own added input — asserted in tests |
| Our sidecar compromised at creation time | Worst case: it creates a lock with attacker beneficiary — visible immediately in the parameter echo + on KasCov before the team announces; cannot touch *existing* locks (consensus holds them) |
| Silverscript compiler bug | Not in trust base — frozen raw bytecode is the artifact (§2) |

**Residual risks we accept and disclose:** consensus-level bugs in the young covenant opcodes
(mitigated by mainnet canary soak, §9), and the KCC-20 standard itself evolving (v1.5 gated on
its stabilization).

---

## 5. Dagger integration

### 5.1 New sidecar routes (kron-service, same 127.0.0.1 + `x-dagger-token` guard)

```
POST /lock-create     {payer, beneficiary, amountSompi | {tick, amount}, startMs, cliffMs,
                       periodMs, nPeriods, template: "LOCK_V1"|"GRANT_V1", [cancelKeys]}
                      → validates §3.4, shards if needed, builds+signs+broadcasts creation tx
                      → { covenantIds[], txids[], scheduleEcho }
POST /lock-claim      {covenantId, beneficiarySecretRef} → builds claim tx (auto A vs B path,
                       max claimable), adds fee input, signs, broadcasts → {txid, claimed, remaining}
GET  /lock-status     ?covenantId= → {params, remaining, vested, claimable, nextUnlockMs,
                       lineage[], shardGroup}
GET  /locks-by-token  ?tick= → aggregate: total locked, % of supply, schedules, verifier verdict
GET  /lock-verify     ?covenantId= → {templateMatch: bool, templateVersion, constants,
                       badgeTier}   // the badge endpoint — pure read, cacheable
GET  /locks-by-address ?address= → locks where address is beneficiary (claim UX)
```
`/lock-verify` and `/locks-by-token` are read-only → also exposed through the scanner sidecar
allowlist (same pattern as the existing 6 read-only routes).

### 5.2 Bot commands (dagger-bot)

- `/lock` — wizard: asset → amount → beneficiary → schedule presets (6mo cliff + 18mo daily;
  12mo linear; custom) → parameter echo → typed confirm → creation → shareable
  confirmation card with KasCov lineage link.
- `/locks` — your locks (as payer or beneficiary): progress bars, next unlock, claimable now.
- `/claim` — one-tap claim of everything claimable across your locks.
- Group-chat flex: `/locks <TICK>` posts the token's lock summary card (drives the badge viral —
  same growth mechanic as PnL cards).

### 5.3 Scanner + market-card badge

- `scanner-bot /scan` output and dagger-bot token cards gain a lock line:
  `🔒 Team: 34% of supply vesting until 2027-02-01 (verified)` ← only when `/lock-verify`
  says `templateMatch: true`. Unverifiable = no badge, ever.
- KasCov deep link on every badge (existing kascov URL scheme in config).

### 5.4 Lock registry

Sidecar keeps a lightweight index (covenantId → params, shard groups, tick) discovered from
creation txs we broadcast **plus** a chain-scan for foreign locks matching our template hashes —
locks created by the standalone CLI (§5.5) or competitors-using-our-template get badges too.
The template is a public standard; the badge network effect is ours.

### 5.5 Standalone open-source claim CLI

Small repo (TS, WASM SDK): given a covenant id + beneficiary key, builds and broadcasts a claim.
This is the "Dagger can vanish and your funds don't care" proof — a launch-post talking point
and an audit-scope item. Publish under ItsGoonBoyCrypto, MIT.

### 5.6 Fees

- Team locks: **flat creation fee** (e.g. 25 KAS per lock group, promo codes apply) — % fees
  would discourage the exact behavior we want to make universal. Collected via the existing
  inline fee flow to the fee wallet.
- Grants/streams (phase 2): flat + 0.25% of stream value, capped.
- Claims: free (network fee only) — never tax the beneficiary.

---

## 6. Phase 2 preview — Streams (payroll/grants)

Same template family, PERIOD_MS = 60_000, GRANT_V1 with Path C. Employer tops up by creating a
new shard (append-only; no mutable-amount complexity). `/stream` command, recipient sees
"salary streaming: 41,096 KAS accrued today." Defer all of it until Locks v1 has a month of
clean mainnet history — this section exists so v1 template decisions don't paint us out of v2
(they don't: streams = same paths, different constants + Path C).

Phase 3 (subscriptions/pull-payments) intentionally unspecced — different trust shape
(merchant-pull), revisit after streams.

---

## 7. The verifier — root of trust

The badge is only as good as verification. Design:

1. Audited artifacts = two frozen bytecode templates (`LOCK_V1`, `GRANT_V1`) with placeholder
   slots for constants. Hash of the *masked* template (constants zeroed) is pinned in
   sidecar config AND published (website, GitHub, launch post).
2. `/lock-verify` fetches the covenant's redeem script (KasCov API / node), masks the constant
   slots, hashes, compares to pinned hash. Extracts constants → recomputes schedule → returns
   structured verdict. **No bytecode heuristics, no "looks like a lock" — exact match or no badge.**
3. Any future template version = new hash, new audit, badge shows version.

---

## 8. Build plan

**Phase 0 — TN10 research spike (no product code):**
validate lock_time semantics (§2), KIP-20 continuation mechanics for our shape, KCC-20
owner-transfer semantics, and what standard KRON/LFG tokens use (§3.5). Deliverable: findings
doc + a hand-built lock covenant surviving create → partial claim → final claim on TN10.
**Kill/pivot criteria live here** — e.g. if lock_time introspection can't serve as a time
oracle, redesign around DAA-score before writing more code.

**Phase 1 — KAS Locks v1 (mainnet, owner-gated):**
template freeze → internal audit (§9) → sidecar routes → bot wizard → verifier + badge →
mainnet canary (small real KAS lock, ≥1 week soak with real claims) → owner-gated beta
(the Gates pattern) → founder allowlist → public.

**Phase 1.5 — KCC-20 locks:** gated entirely on Phase 0 findings re: token standards.

**Phase 2 — Streams.** After ≥1 month clean v1 mainnet history.

Each go-live follows house rules: git push both repos, refresh the TG user guide, update
website features, security-audit doc updated.

---

## 9. Audit & test gates (ALL must pass before any mainnet funds beyond canary)

**A. Script-level (the covenant itself):**
- [ ] Unit tests against the rusty-kaspa script interpreter (vendored test harness): every path,
      every `require`, boundary times (cliff-1ms / cliff / end / end+1ms), k=0, k=N, claim-more-
      than-claimable rejected, claim-to-wrong-spk rejected, missing continuation rejected,
      continuation with reduced-below-floor amount rejected, wrong-covenant-id rejected
- [ ] Property/fuzz tests: random (TOTAL, N, PERIOD, claim sequences) → invariant: sum of all
      beneficiary outputs over any tx sequence ≤ vested(t) at every step; no sequence extracts
      early; final sweep leaves zero
- [ ] Overflow proofs for §3.3 caps written down, and fuzzer seeded with adversarial near-cap values
- [ ] Adversarial tx construction suite: fee-from-lock attempts, multi-input covenant collisions
      (two locks in one tx), malleated constants, Path C absent from LOCK_V1 confirmed by
      bytecode diff, third-party-signed claims rejected
- [ ] Compute-budget + storage-mass measurement for worst-case claim tx (document actual fees)

**B. Infrastructure-level (sidecar/bot):**
- [ ] §3.4 creation validation tests incl. shard math
- [ ] Verifier: true template → match; every single-byte mutation of the template → NO match
      (exhaustive byte-flip test); foreign-lock discovery test
- [ ] Route auth (existing token guard), no covenant secrets in logs, beneficiary secretRef
      handling follows existing wallet-encryption pattern
- [ ] Claim CLI end-to-end with zero Dagger infra running

**C. Network-level:**
- [ ] Full lifecycle on TN10 ×3 schedules (incl. one sharded, one cliff-only)
- [ ] Mainnet canary: our own KAS, small, full lifecycle incl. a claim every day for a week
- [ ] Reorg behavior observed on TN10 (claim tx during DAG merge conditions)

**D. Review:**
- [ ] Internal line-by-line audit doc (SECURITY_AUDIT_YYYY-MM-DD.md pattern) — script bytecode
      annotated op-by-op with the invariant each op serves
- [ ] Second-pass adversarial review in a fresh session ("try to steal from this template" red-team)
- [ ] External audit decision: for KAS-only v1 with template-hash trust model, internal +
      red-team may suffice for beta; **before KCC-20 locks or >$100k TVL, get an external
      review** (Sherlock audited Kaskad — ecosystem precedent exists). Budget line item, not optional.
- [ ] Public docs: template hashes published, threat model (§4) published on website — the
      transparency is part of the product

---

## 10. Open questions (tracked; Phase 0 resolves most)

1. lock_time introspection semantics + finality/sequence requirements (§2) — **blocking**
2. KCC-20 covenant-owner transfer mechanics (§3.5) — blocks v1.5 only
3. KRON/LFG launch token standard today (§3.5) — determines wedge timing
4. KasCov API surface for redeem-script fetch (verifier §7) — fallback: direct node RPC
5. Does the WASM SDK v2 / @kronsdk 0.17.1 expose covenant-binding tx construction, or do we
   build raw tx JSON against the node? (affects sidecar effort estimate)
6. Silverscript pinning: which commit, and do we use it at all vs pure hand-written script
7. Fee number (25 KAS placeholder) + whether launchpads get a partner rate
