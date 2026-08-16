# DagLock — Mainnet Test Spec (owner runbook)

Purpose: validate DagLock (LOCK_V1) on **Kaspa mainnet with real KAS**, end to end, before any
public wiring. You run every step from a terminal; the tool (`src/mainnet_admin.js`) is dry-run by
default and never broadcasts without `--confirm`. Budget: **~10–15 KAS total** (locks are tiny; the
rest is fees + buffer). Time: ~40 min including waits.

> Safety rails already built in: dry-run default, a `DAGLOCK_MAX_KAS` cap (default 25), full
> parameter echo before every broadcast, and F1/F2 protections (genesis value must equal TOTAL;
> claims signed SIGHASH_ALL). The admin wallet is a **burner** — key stored in plaintext in
> `mainnet_state.json`. Never reuse a wallet that holds meaningful funds.

## 0. Prerequisites

- Node 22+ and the repo at `dagger/locks-covenant`.
- From `dagger/locks-covenant`, deps installed once: `npm install` (pulls the vendored kaspa WASM
  through kron-sdk — same dependency the live bot uses).
- A little KAS you can send to a fresh burner address (~15 KAS).

Run everything from:
```bash
cd dagger/locks-covenant
```

## 1. Create + fund the burner admin wallet

```bash
node src/mainnet_admin.js gen
```
- Prints a `kaspa:` mainnet address. **Send ~15 KAS to it** from your wallet.
- Confirm it landed:
```bash
node src/mainnet_admin.js balance
```
- ✅ Expect: `balance: ~15 KAS`, `utxos: 1+`.

## 2. Fast smoke lock (short schedule so the whole lifecycle runs in ~15 min)

Schedule: 2 KAS total, 5-min cliff, 5-min periods, 4 periods (= fully vested 20 min after start).

**2a. Dry-run first (no broadcast) — read the echo carefully:**
```bash
node src/mainnet_admin.js create 2 5 5 4
```
- ✅ Expect a `LOCK TO BE CREATED` block. **Verify by eye:** total = 2 KAS, beneficiary address is
  your burner, dates look right (~5 min cliff, ends ~20 min out), lock addr printed. No broadcast.

**2b. Broadcast it:**
```bash
node src/mainnet_admin.js create 2 5 5 4 --confirm
```
- ✅ Expect `✅ BROADCAST. lock kaspa:… tx …`. The lock + covid are saved to `mainnet_state.json`.

## 3. Verify the badge (F1 funding integrity)

```bash
node src/mainnet_admin.js verify
```
- ✅ Expect: `verified: true  funded: true  reason: ok`, a `fingerprint:` equal to
  **`c8e2b56863dfee8cfe50ad765b5dc448e44e052d3b86b0ceec0591d5611e33d9`**, the terms echoed, and
  `current on-chain locked: 2 KAS`.
- This confirms the on-chain script is a genuine LOCK_V1 **and** the funded amount equals TOTAL.

## 4. Watch it vest

```bash
node src/mainnet_admin.js status
```
- Before the cliff: `claimable: 0` (floor == full 2 KAS). Re-run every few minutes.
- ✅ After ~7–8 min (cliff matures in median-time, which lags wall-clock ~1–2 min): `claimable > 0`.

Note: mainnet median-time lags real time by ~1–2 min (less than testnet's ~130s). The tool anchors
`lock_time` to the node's median-time automatically — you don't manage it.

## 5. Partial claim (the core test)

```bash
node src/mainnet_admin.js claim            # dry-run: shows "partial  claimable=… re-lock floor=…"
node src/mainnet_admin.js claim --confirm  # broadcast
```
- ✅ Expect `✅ partial claim broadcast: …`.
- Re-check:
```bash
node src/mainnet_admin.js status
```
- ✅ Expect `remaining` dropped to the floor, `utxos: 1` (the lock continued under the **same covid**
  — check `verify` still shows the same fingerprint and `funded`/lineage intact). This proves the
  recursion + continuation floor held on mainnet.

## 6. Final claim (terminate)

Wait until fully vested (~20 min after create). Then:
```bash
node src/mainnet_admin.js status           # should show floor: 0, claimable == remaining
node src/mainnet_admin.js claim --confirm   # FINAL claim (no continuation; sweeps remainder)
node src/mainnet_admin.js status           # remaining: 0, utxos: 0
```
- ✅ Expect `✅ FINAL claim broadcast`, then `remaining: 0 / 2 KAS, utxos: 0`. The covenant is closed
  and every sompi is accounted for.

## 7. (Optional) Adversarial confirmation on mainnet

To prove theft is rejected by mainnet consensus (not just testnet), create a fresh short lock and
run the adversarial battery against it. Point the matrix at mainnet by editing the top of
`src/adversarial_matrix.js` (`const NETWORK = "mainnet"`) and using the mainnet wallet, OR just trust
the identical result already proven on TN10 + the Rust harness. Recommended only if you want belt-
and-suspenders on real consensus; costs ~1–2 KAS in fees for the rejected txs (rejections are free;
only the honest control consumes value).

## 8. Cleanup

- Sweep any leftover KAS from the burner back to your main wallet (send from the burner using your
  own tooling, or leave the dust).
- To start a fresh test, delete the `lock` object from `mainnet_state.json` (or the whole file to
  rotate the burner wallet).

## Pass criteria (all must hold)

- [ ] `verify` → `verified: true, funded: true`, fingerprint matches the published value.
- [ ] Dry-run echoes are correct **before** each `--confirm`.
- [ ] Partial claim: claimed ≤ vested; remainder re-locked at floor under the same covid.
- [ ] Final claim: sweeps remainder, `utxos: 0`, nothing stranded.
- [ ] At no point can you claim more than has vested (the tool refuses; consensus would too).
- [ ] Total spent ≈ lock amount you chose + a few cents of KAS in fees.

## If something looks wrong — STOP

Do not proceed to public/admin-bot wiring. Capture the tx id + the tool output and we diagnose. The
covenant has been audited, red-teamed, and validated on testnet + the real interpreter, so a mainnet
surprise most likely means an environment/param issue — but treat any anomaly as blocking.

## Costs summary

| Item | KAS |
|---|---|
| Smoke lock principal (recovered via claims) | 2 |
| Network fees (create + ~5 claims) | < 0.1 |
| Buffer / optional adversarial run | ~10 |
| **Recommended burner funding** | **~15** |
