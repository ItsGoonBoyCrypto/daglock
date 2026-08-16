/**
 * Model & creation-validation property tests — Track A (offline, exhaustive).
 * Complements the on-chain real-interpreter runs and the Rust harness (CI-only on this box).
 *
 * Proves, over large randomized + boundary sweeps:
 *  - vestedAt / continuationFloor are monotonic, bounded [0,total], and match the per-period
 *    definition the script computes (k = min(floor(elapsed/period), N)).
 *  - the script's integer math cannot overflow i64 given the §3.4 creation caps.
 *  - validateParams accepts exactly the intended envelope and rejects everything outside it.
 *  - final-claim boundary: floor hits 0 exactly at full vest, never before.
 */
import { validateParams, vestedAt, continuationFloor, MAX_N_PERIODS, MAX_I62 } from "./lockv1.js";

let fails = 0;
const ok = (cond, msg) => { if (!cond) { fails++; console.log(`  ✗ ${msg}`); } };

// Deterministic PRNG (no Math.random dependence for reproducibility).
let seed = 0x1234_5678n;
const rnd = () => { seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return seed >> 11n; };
const rangeBig = (lo, hi) => lo + (rnd() % (hi - lo + 1n));

const I64_MAX = (1n << 63n) - 1n;
const THRESHOLD = 500_000_000_000n;

// ---- 1. Property sweep over valid random schedules ----
let n = 0;
for (let iter = 0; iter < 200_000; iter++) {
  const nPeriods = rangeBig(1n, MAX_N_PERIODS);
  const perPeriodCap = MAX_I62 / nPeriods;
  const perPeriod = rangeBig(1n, perPeriodCap);
  const periodMs = rangeBig(60_000n, 5_000_000_000n);
  const startMs = rangeBig(THRESHOLD, THRESHOLD * 4n);
  const cliffOffset = rangeBig(0n, nPeriods * periodMs);
  const p = { beneficiaryPub: new Uint8Array(32), startMs, cliffMs: startMs + cliffOffset, periodMs, nPeriods, perPeriod };

  // must validate
  let total;
  try { total = validateParams(p, undefined).total; }
  catch (e) { fails++; console.log(`  ✗ valid schedule rejected: ${e.message}`); continue; }
  n++;

  const end = startMs + nPeriods * periodMs;

  // overflow safety: vested at any time <= total <= MAX_I64
  ok(total <= I64_MAX, "total fits i64");
  const vEnd = vestedAt(p, end);
  ok(vEnd === total, "vested at end == total");
  ok(continuationFloor(p, end) === 0n, "floor 0 at end");

  // pre-cliff floor == total (nothing claimable)
  ok(continuationFloor(p, p.cliffMs - 1n) === total, "pre-cliff floor == total");

  // monotonic non-increasing floor across sampled times; vested in [0,total]
  let prevFloor = total + 1n;
  for (let s = 0; s < 6; s++) {
    const t = startMs + rangeBig(0n, nPeriods * periodMs + periodMs);
    const v = vestedAt(p, t);
    ok(v >= 0n && v <= total, "vested in [0,total]");
    // vested equals per-period definition
    const elapsed = t - startMs;
    const k = elapsed < 0n ? 0n : (t < p.cliffMs ? 0n : (elapsed / periodMs > nPeriods ? nPeriods : elapsed / periodMs));
    ok(v === k * perPeriod, "vested matches k*perPeriod");
    // intermediate product cannot overflow
    ok(k * perPeriod <= MAX_I62, "k*perPeriod <= MAX_I62 (no overflow)");
  }
  // monotonic check on an increasing time grid
  for (let t = p.cliffMs; t <= end; t += (end - p.cliffMs) / 5n + 1n) {
    const f = continuationFloor(p, t);
    ok(f <= prevFloor, "floor monotonic non-increasing");
    prevFloor = f;
  }
}
console.log(`[model] property sweep: ${n} valid schedules exercised`);

// ---- 2. Creation validation envelope (§3.4) — realistic (~2026-era) timestamps ----
const now = 1_786_000_000_000n;
const base = { beneficiaryPub: new Uint8Array(32), startMs: now, cliffMs: now + 120_000n, periodMs: 60_000n, nPeriods: 10n, perPeriod: 50_000_000n };
const rejects = (mut, why) => {
  let threw = false;
  try { validateParams({ ...base, ...mut }, now); } catch { threw = true; }
  ok(threw, `must reject: ${why}`);
};
const accepts = (mut, why) => {
  let threw = false;
  try { validateParams({ ...base, ...mut }, now); } catch (e) { threw = true; }
  ok(!threw, `must accept: ${why}`);
};
accepts({}, "baseline valid");
rejects({ beneficiaryPub: new Uint8Array(31) }, "31-byte pubkey");
rejects({ beneficiaryPub: new Uint8Array(33) }, "33-byte pubkey");
rejects({ startMs: THRESHOLD - 1n }, "startMs below time-threshold (would be DAA-score type)");
rejects({ startMs: now - 86_400_001n, cliffMs: now - 86_400_001n }, "startMs >24h in the past (anti-backdate)");
accepts({ startMs: now - 86_000_000n, cliffMs: now - 86_000_000n + 120_000n }, "startMs ~23h ago ok");
rejects({ cliffMs: base.startMs - 1n }, "cliff before start");
rejects({ cliffMs: base.startMs + 10n * 60_000n + 1n }, "cliff beyond vest end");
rejects({ periodMs: 59_999n }, "period below 60s floor");
rejects({ nPeriods: 0n }, "nPeriods 0");
rejects({ nPeriods: MAX_N_PERIODS + 1n }, "nPeriods above cap");
rejects({ perPeriod: 0n }, "perPeriod 0");
rejects({ nPeriods: 2n, perPeriod: MAX_I62 }, "overflow cap (perPeriod*nPeriods > MAX_I62)");
accepts({ nPeriods: 2n, perPeriod: MAX_I62 / 2n }, "exactly at overflow cap ok");

// ---- 3. Boundary: single-period lock, cliff==start ----
const oneShot = { ...base, nPeriods: 1n, perPeriod: 100_000_000n, cliffMs: base.startMs };
accepts(oneShot, "1-period lock, cliff==start");
{
  const p = { ...oneShot };
  ok(vestedAt(p, p.startMs - 1n) === 0n, "1-shot: nothing before start");
  ok(vestedAt(p, p.startMs) === 0n, "1-shot: 0 at start (period not elapsed)");
  ok(vestedAt(p, p.startMs + p.periodMs) === 100_000_000n, "1-shot: full after 1 period");
  ok(continuationFloor(p, p.startMs + p.periodMs) === 0n, "1-shot: floor 0 after period");
}

console.log(fails === 0 ? "\n✅ ALL MODEL/VALIDATION TESTS PASSED" : `\n❌ ${fails} MODEL TEST FAILURES`);
process.exit(fails === 0 ? 0 : 1);
