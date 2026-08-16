/**
 * Verifier tests — Track B of the §9 gate. Pure JS, no WASM.
 *  1. A real LOCK_V1 verifies and round-trips its params.
 *  2. Exhaustive single-byte mutation (every offset × every byte value): every mutant either fails
 *     verification, or still verifies AND its extracted params re-encode to the exact mutated bytes
 *     (i.e. only a constant slot changed — never the opcode skeleton, so no hidden behavior).
 *  3. Length mutations (truncate / extend) rejected.
 *  4. Non-lock scripts rejected.
 *  5. Internal-consistency: a script whose embedded TOTAL != nPeriods*perPeriod is rejected.
 */
import { buildLockRedeemJS, bytesToHex } from "./lockv1.js";
import { verifyLock, fingerprint, badgeTier, evaluateBadge, describeLock, BADGE } from "./verify.js";

let fails = 0;
const ok = (cond, msg) => { if (!cond) { fails++; console.log(`  ✗ ${msg}`); } };

const params = {
  beneficiaryPub: new Uint8Array(32).fill(0xAB),
  startMs: 700_000_000_000n,
  cliffMs: 700_000_120_000n,
  periodMs: 60_000n,
  nPeriods: 180n,
  perPeriod: 100_000_000n, // 1 KAS/period => 180 KAS
};
const redeem = buildLockRedeemJS(params);
console.log(`[test] redeem ${redeem.length} bytes, template fingerprint ${fingerprint().slice(0, 16)}…`);

// 1. Real lock verifies + round-trips.
const v = verifyLock(redeem);
ok(v.match, `real lock must verify (reason: ${v.reason})`);
if (v.match) {
  ok(v.params.startMs === params.startMs, "startMs round-trip");
  ok(v.params.cliffMs === params.cliffMs, "cliffMs round-trip");
  ok(v.params.periodMs === params.periodMs, "periodMs round-trip");
  ok(v.params.nPeriods === params.nPeriods, "nPeriods round-trip");
  ok(v.params.perPeriod === params.perPeriod, "perPeriod round-trip");
  ok(bytesToHex(v.params.beneficiaryPub) === bytesToHex(params.beneficiaryPub), "pubkey round-trip");
  ok(v.total === params.nPeriods * params.perPeriod, "total consistency");
}

// 2. Exhaustive single-byte mutation.
let mutTested = 0, rejected = 0, verifiedConst = 0, skeletonBreaks = 0;
for (let i = 0; i < redeem.length; i++) {
  for (let b = 0; b < 256; b++) {
    if (b === redeem[i]) continue;
    const m = redeem.slice();
    m[i] = b;
    mutTested++;
    const r = verifyLock(m);
    if (!r.match) { rejected++; continue; }
    verifiedConst++;
    // A still-verifying mutant MUST re-encode (via the audited builder) to exactly the mutated bytes.
    // verifyLock already enforces this via its internal rebuild check; assert independently here too.
    const rebuilt = buildLockRedeemJS(r.params);
    if (bytesToHex(rebuilt) !== bytesToHex(m)) {
      skeletonBreaks++; fails++;
      console.log(`  ✗ mutation @${i}=0x${b.toString(16)} verified but rebuild != mutated (HIDDEN-BEHAVIOR RISK)`);
    }
  }
}
console.log(`[test] byte-flip: ${mutTested} mutants — ${rejected} rejected, ${verifiedConst} verified-as-constant-change, ${skeletonBreaks} skeleton-breaks`);
ok(skeletonBreaks === 0, "no mutation may alter the opcode skeleton and still verify");

// 3. Length mutations.
ok(!verifyLock(redeem.slice(0, redeem.length - 1)).match, "truncated script rejected");
const extended = new Uint8Array(redeem.length + 1); extended.set(redeem); extended[redeem.length] = 0x51;
ok(!verifyLock(extended).match, "extended script rejected");

// 4. Non-lock scripts.
ok(!verifyLock(new Uint8Array([0x51])).match, "OpTrue-only rejected");
ok(!verifyLock(new Uint8Array([0xaa, 0x20, ...new Array(32).fill(1), 0x87])).match, "arbitrary p2sh-ish rejected");

// 5. Internal-consistency attack: craft a valid skeleton whose embedded TOTAL is wrong.
//    Build honestly, then find & corrupt the TOTAL push so it no longer equals N*perPeriod.
//    We do this by building with a builder variant that lies about total.
function buildWithWrongTotal(p, wrongTotal) {
  // Re-encode manually: same as buildLockRedeemJS but substitute the total constant.
  const good = buildLockRedeemJS(p);
  const goodTotalOnly = buildLockRedeemJS({ ...p }); // reference
  // Simplest: rebuild the whole thing swapping total by temporarily monkeypatching is messy;
  // instead assert the verifier's total check via a hand-built mismatch using two locks.
  return { good, goodTotalOnly };
}
// Practical check: take a lock with nPeriods=180,perPeriod=1e8 (total 1.8e10). Build a DIFFERENT lock
// with the same skeleton positions but nPeriods=181 (total 1.81e10) — its total slot is self-consistent,
// so that's a valid different lock, not an attack. The real attack (total != N*perPeriod) cannot be
// produced by the honest builder, so we synthesize it by splicing.
{
  const good = buildLockRedeemJS(params);
  // Locate the TOTAL push: it is the constant right before OpSwap(0x7c) OpSub(0x94). Find 0x7c 0x94.
  let idx = -1;
  for (let i = 0; i < good.length - 1; i++) if (good[i] === 0x7c && good[i + 1] === 0x94) { idx = i; break; }
  ok(idx > 0, "found OpSwap/OpSub anchor for total splice");
  if (idx > 0) {
    // The byte immediately before OpSwap is the last byte of the TOTAL push; flip it to break N*perPeriod.
    const spliced = good.slice();
    spliced[idx - 1] ^= 0x01;
    const rr = verifyLock(spliced);
    // Either the splice broke minimal-encoding/skeleton (reject) or changed total => total!=N*perPeriod (reject).
    ok(!rr.match, `total-inconsistency splice rejected (reason: ${rr.reason})`);
  }
}

// 6. Badge tiers (test params use 1-min periods, so duration is short => never STRONG).
ok(badgeTier(params, 180_00000000n, 1000_00000000n) === BADGE.PARTIAL, "18% locked => PARTIAL");
ok(badgeTier(params, 40_00000000n, 1000_00000000n) === BADGE.TRIVIAL, "4% locked => TRIVIAL");
ok(badgeTier(params, 0n, 0n) === BADGE.NONE, "unknown supply => NONE");
// STRONG requires >=20% supply AND >=6mo duration.
const strongParams = { ...params, periodMs: 86_400_000n, nPeriods: 200n }; // 200 days
ok(badgeTier(strongParams, 250_00000000n, 1000_00000000n) === BADGE.STRONG, "25% + 200d => STRONG");
console.log(`[test] tiers: 18%/short=${badgeTier(params, 180_00000000n, 1000_00000000n)}, 25%/200d=${badgeTier(strongParams, 250_00000000n, 1000_00000000n)}`);

// 7. F1 — on-chain funding integrity: badge only when genesis value == TOTAL.
{
  const strongParams = { ...params, periodMs: 86_400_000n, nPeriods: 200n, perPeriod: 100_000_000n }; // 200 KAS, 200d
  const total = strongParams.nPeriods * strongParams.perPeriod; // 20_000_000_000
  const rd = buildLockRedeemJS(strongParams);
  const supply = 100_000_000_000n; // total locked = 20% of supply

  const good = evaluateBadge({ redeem: rd, genesisValueSompi: total, currentAmountSompi: total, tokenSupplyBase: supply });
  ok(good.verified && good.funded && good.badge === BADGE.STRONG, `correctly-funded lock => STRONG (got ${good.badge}, ${good.reason})`);

  const over = evaluateBadge({ redeem: rd, genesisValueSompi: total + 5_000_000_000n, currentAmountSompi: total + 5_000_000_000n, tokenSupplyBase: supply });
  ok(over.badge === BADGE.NONE && over.funded === false, `OVER-funded => NO badge (got ${over.badge}, ${over.reason})`);

  const under = evaluateBadge({ redeem: rd, genesisValueSompi: total - 1n, currentAmountSompi: total - 1n, tokenSupplyBase: supply });
  ok(under.badge === BADGE.NONE && under.funded === false, `UNDER-funded => NO badge (got ${under.badge}, ${under.reason})`);

  const noGenesis = evaluateBadge({ redeem: rd, currentAmountSompi: total, tokenSupplyBase: supply });
  ok(noGenesis.badge === BADGE.NONE, "unknown genesis value => NO badge (cannot confirm funded==TOTAL)");

  const notLock = evaluateBadge({ redeem: new Uint8Array([0x51]), genesisValueSompi: total });
  ok(notLock.badge === BADGE.NONE && notLock.verified === false, "non-lock script => NO badge");
  console.log(`[test] F1 funding-integrity: good=${good.badge}, over/under/unknown all NONE`);
}

// 8. F4 — describeLock surfaces terms for the consumer to confirm.
{
  const d = describeLock(params);
  ok(d.beneficiaryPubHex === bytesToHex(params.beneficiaryPub), "describe: pubkey surfaced for consumer confirmation");
  ok(BigInt(d.total) === params.nPeriods * params.perPeriod, "describe: total matches schedule");
  ok(typeof d.start === "string" && typeof d.cliff === "string" && typeof d.end === "string", "describe: human dates present");
  ok(d.confirmPrompt.includes("YOURS"), "describe: includes consumer-confirm prompt (F4)");
  console.log(`[test] F4 describe: ${d.totalDisplay} over ${d.nPeriods} periods, ${d.durationDays}d, ends ${d.end.slice(0, 10)}`);
}

console.log(fails === 0 ? "\n✅ ALL VERIFIER TESTS PASSED" : `\n❌ ${fails} VERIFIER TEST FAILURES`);
process.exit(fails === 0 ? 0 : 1);
