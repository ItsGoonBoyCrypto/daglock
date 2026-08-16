/**
 * LOCK_V1 — Dagger Locks vesting covenant (Phase 0 / TN10 ONLY — NOT AUDITED, NOT FOR MAINNET).
 *
 * Design (see dagger/docs/LOCKS_SPEC.md):
 *  - State = the covenant UTXO's own amount; all schedule params are immutable script constants,
 *    so the P2SH address is static for the lock's whole life.
 *  - Continuation floor = TOTAL - vested(now): balance-independent, so the script never reads
 *    its own amount. Once fully vested the floor hits 0 and the covenant may terminate.
 *  - Continuation lives at output[own_input_index] (OpTxInputIndex), so multiple shards of the
 *    same lock compose in one claim tx with no cross-satisfaction.
 *  - Claims require the beneficiary's Schnorr signature — no third-party grief-claims, and no
 *    need to pin a beneficiary payout output (the signer owns the claimed funds by definition).
 *  - Time base: median-time milliseconds via tx.lock_time. A single OpCheckLockTimeVerify on
 *    CLIFF_MS simultaneously (a) enforces the cliff, (b) pins lock_time to the Time
 *    interpretation (>= LOCK_TIME_THRESHOLD = 500e9, so a DAA-score value can't be smuggled
 *    into the vesting math), and (c) rejects inputs with a finalized sequence — closing the
 *    "all sequences = u64::MAX skips lock_time validation" bypass
 *    (rusty-kaspa tx_validation_in_header_context.rs::check_tx_is_finalized).
 *  - Lineage: output[i] must carry the same KIP-20 covenant id as input[i]
 *    (OpOutputCovenantId == OpInputCovenantId), making the KasCov trail script-enforced.
 *
 * Claim witness: <schnorr_sig(65B: 64 sig + 1 sighash byte)>; sigscript = <sig> <redeem>.
 */

export const LOCK_TIME_THRESHOLD = 500_000_000_000n; // below: DAA score; at/above: unix ms
export const MAX_N_PERIODS = 10_000n;
export const MAX_I62 = (1n << 62n) - 1n;

/** Validate schedule params (spec §3.4). All bigint ms/sompi. Throws on violation. */
export function validateParams(p, nowMs) {
  const { startMs, cliffMs, periodMs, nPeriods, perPeriod } = p;
  if (!(p.beneficiaryPub instanceof Uint8Array) || p.beneficiaryPub.length !== 32)
    throw new Error("beneficiaryPub must be a 32-byte x-only schnorr pubkey");
  if (startMs < LOCK_TIME_THRESHOLD) throw new Error("startMs must be a unix-ms timestamp");
  if (nowMs !== undefined && startMs < nowMs - 86_400_000n)
    throw new Error("startMs more than 24h in the past (badge anti-backdating)");
  if (cliffMs < startMs) throw new Error("cliffMs must be >= startMs");
  if (cliffMs > startMs + nPeriods * periodMs) throw new Error("cliff beyond vest end");
  if (periodMs < 60_000n) throw new Error("periodMs must be >= 60s");
  if (nPeriods < 1n || nPeriods > MAX_N_PERIODS) throw new Error(`nPeriods must be 1..${MAX_N_PERIODS}`);
  if (perPeriod < 1n) throw new Error("perPeriod must be >= 1");
  if (perPeriod > MAX_I62 / nPeriods) throw new Error("overflow cap: perPeriod * nPeriods must fit i62 (shard the lock)");
  return { total: nPeriods * perPeriod };
}

/** Build the LOCK_V1 redeem script. `k` = loaded kaspa WASM module. Returns Uint8Array. */
export function buildLockRedeem(k, p) {
  const { total } = validateParams(p);
  const O = k.Opcodes;
  const sb = new k.ScriptBuilder();
  sb.addData(p.beneficiaryPub);           // [sig, pub]
  sb.addOp(O.OpCheckSigVerify);           // beneficiary-only claims
  sb.addI64(p.cliffMs);                   // CLTV: cliff + Time-type pin + seq-not-final
  sb.addOp(O.OpCheckLockTimeVerify);
  sb.addOp(O.OpTxLockTime);               // now (trusted lower bound on median time)
  sb.addI64(p.startMs);
  sb.addOp(O.OpSub);                      // elapsed
  sb.addI64(p.periodMs);
  sb.addOp(O.OpDiv);                      // k' = floor(elapsed / period)
  sb.addI64(p.nPeriods);
  sb.addOp(O.OpMin);                      // k = min(k', N)
  sb.addI64(p.perPeriod);
  sb.addOp(O.OpMul);                      // vested = k * perPeriod
  sb.addI64(total);
  sb.addOp(O.OpSwap);
  sb.addOp(O.OpSub);                      // floor = TOTAL - vested
  sb.addOp(O.OpDup);
  sb.addI64(0n);
  sb.addOp(O.OpGreaterThan);              // floor > 0 ?
  sb.addOp(O.OpIf);                       //   [floor]
  sb.addOp(O.OpTxInputIndex);
  sb.addOp(O.OpTxOutputAmount);           //   [floor, out[i].amount]
  sb.addOp(O.OpLessThanOrEqual);
  sb.addOp(O.OpVerify);                   //   floor <= out[i].amount
  sb.addOp(O.OpTxInputIndex);
  sb.addOp(O.OpTxOutputSpk);
  sb.addOp(O.OpTxInputIndex);
  sb.addOp(O.OpTxInputSpk);
  sb.addOp(O.OpEqualVerify);              //   out[i].spk == own spk (recursion)
  sb.addOp(O.OpTxInputIndex);
  sb.addOp(O.OpOutputCovenantId);
  sb.addOp(O.OpTxInputIndex);
  sb.addOp(O.OpInputCovenantId);
  sb.addOp(O.OpEqualVerify);              //   out[i].covid == own covid (lineage)
  sb.addOp(O.OpElse);
  sb.addOp(O.OpDrop);                     //   fully vested: drop floor
  sb.addOp(O.OpEndIf);
  sb.addOp(O.OpTrue);
  const hex = sb.toString();
  sb.free?.(); // release WASM-side allocation (critical: this is called thousands of times in tests)
  return hexToBytes(hex);
}

// ---- Pure-JS builder (no WASM) — replicates kaspa ScriptBuilder add_i64/add_data exactly.
// Used by the verifier so the badge sidecar needs no WASM, and cross-checked byte-for-byte
// against the WASM builder in tests.
const OPC = {
  Op0: 0x00, Op1Negate: 0x4f, OpData1: 0x01,
  OpCheckSigVerify: 0xad, OpCheckLockTimeVerify: 0xb0, OpTxLockTime: 0xb5,
  OpSub: 0x94, OpDiv: 0x96, OpMul: 0x95, OpMin: 0xa3,
  OpGreaterThan: 0xa0, OpLessThanOrEqual: 0xa1, OpDup: 0x76, OpSwap: 0x7c, OpDrop: 0x75,
  OpIf: 0x63, OpElse: 0x67, OpEndIf: 0x68, OpVerify: 0x69, OpEqualVerify: 0x88, OpTrue: 0x51,
  OpTxInputIndex: 0xb9, OpTxOutputAmount: 0xc2, OpTxOutputSpk: 0xc3, OpTxInputSpk: 0xbf,
  OpInputCovenantId: 0xcf, OpOutputCovenantId: 0xd5,
};

// Minimal little-endian sign-magnitude encoding (mirrors serialize_i64 in rusty-kaspa).
export function serializeScriptNum(n) {
  if (n === 0n) return [];
  const sign = n < 0n ? -1 : 1;
  let positive = n < 0n ? -n : n;
  const bytes = [];
  let lastSat = false;
  while (positive !== 0n) {
    const byte = Number(positive & 0xffn);
    lastSat = (byte & 0x80) !== 0;
    positive >>= 8n;
    bytes.push(byte);
  }
  if (lastSat) bytes.push(0);
  if (sign === -1) bytes[bytes.length - 1] |= 0x80;
  return bytes;
}

function pushData(out, bytes) {
  if (bytes.length === 0) { out.push(OPC.Op0); return; }
  if (bytes.length === 1) {
    const b = bytes[0];
    if (b >= 1 && b <= 16) { out.push(0x50 + b); return; }
    if (b === 0x81) { out.push(OPC.Op1Negate); return; }
    out.push(OPC.OpData1, b); return;
  }
  if (bytes.length <= 0x4b) { out.push(bytes.length, ...bytes); return; }
  if (bytes.length <= 0xff) { out.push(0x4c, bytes.length, ...bytes); return; }
  throw new Error("push too large for lock constants");
}

function addI64(out, n) {
  if (n === 0n) { out.push(OPC.Op0); return; }
  if (n === -1n) { out.push(OPC.Op1Negate); return; }
  if (n >= 1n && n <= 16n) { out.push(0x50 + Number(n)); return; }
  pushData(out, serializeScriptNum(n));
}

/** Pure-JS LOCK_V1 builder — returns Uint8Array identical to buildLockRedeem(k, p). */
export function buildLockRedeemJS(p) {
  const { total } = validateParams(p);
  const o = [];
  pushData(o, Array.from(p.beneficiaryPub));
  o.push(OPC.OpCheckSigVerify);
  addI64(o, p.cliffMs); o.push(OPC.OpCheckLockTimeVerify);
  o.push(OPC.OpTxLockTime); addI64(o, p.startMs); o.push(OPC.OpSub);
  addI64(o, p.periodMs); o.push(OPC.OpDiv);
  addI64(o, p.nPeriods); o.push(OPC.OpMin);
  addI64(o, p.perPeriod); o.push(OPC.OpMul);
  addI64(o, total); o.push(OPC.OpSwap); o.push(OPC.OpSub);
  o.push(OPC.OpDup); addI64(o, 0n); o.push(OPC.OpGreaterThan); o.push(OPC.OpIf);
  o.push(OPC.OpTxInputIndex, OPC.OpTxOutputAmount, OPC.OpLessThanOrEqual, OPC.OpVerify);
  o.push(OPC.OpTxInputIndex, OPC.OpTxOutputSpk, OPC.OpTxInputIndex, OPC.OpTxInputSpk, OPC.OpEqualVerify);
  o.push(OPC.OpTxInputIndex, OPC.OpOutputCovenantId, OPC.OpTxInputIndex, OPC.OpInputCovenantId, OPC.OpEqualVerify);
  o.push(OPC.OpElse, OPC.OpDrop, OPC.OpEndIf, OPC.OpTrue);
  return Uint8Array.from(o);
}

/** P2SH script-public-key + bech32 address for a lock. */
export function lockSpk(k, redeem) { return k.payToScriptHashScript(redeem); }
export function lockAddress(k, redeem, networkId) {
  return k.addressFromScriptPublicKey(lockSpk(k, redeem), networkId).toString();
}

/** Vested amount at a given ms timestamp (mirrors the script math exactly). */
export function vestedAt(p, nowMs) {
  if (nowMs < p.cliffMs) return 0n;
  const elapsed = nowMs - p.startMs;
  if (elapsed < 0n) return 0n;
  let kPeriods = elapsed / p.periodMs;
  if (kPeriods > p.nPeriods) kPeriods = p.nPeriods;
  return kPeriods * p.perPeriod;
}

export function continuationFloor(p, nowMs) {
  const total = p.nPeriods * p.perPeriod;
  const f = total - vestedAt(p, nowMs);
  return f > 0n ? f : 0n;
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export const bytesToHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
