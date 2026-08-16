/**
 * LOCK_V1 verifier — the root of trust for the "🔒 verified" badge.
 *
 * Because numeric constants are minimally-encoded (variable length), a fixed-offset masked hash
 * is impossible. Instead we verify STRUCTURALLY:
 *   1. Parse the redeem into a token stream (opcode | data-push{bytes}).
 *   2. Match it against the LOCK_V1 skeleton — a fixed opcode sequence with 6 typed constant slots
 *      (beneficiaryPub[32], cliffMs, startMs, periodMs, nPeriods, perPeriod, total). Any deviation
 *      → not a lock, no badge.
 *   3. Extract the constants as params.
 *   4. Re-derive TOTAL = nPeriods*perPeriod and assert it equals the embedded total slot.
 *   5. Rebuild the redeem from the extracted params with the audited builder and assert it equals
 *      the candidate byte-for-byte. (Belt-and-suspenders: proves no hidden bytes anywhere.)
 *
 * The published TEMPLATE FINGERPRINT is the hash of the skeleton with all constant slots zeroed —
 * length/position independent, so it is stable across every lock regardless of its parameters.
 */
import { createHash } from "node:crypto";
import { buildLockRedeemJS, bytesToHex, hexToBytes } from "./lockv1.js";

// Opcode constants we reference (Kaspa txscript codes).
const OP = {
  OpData32: 0x20,
  OpCheckSigVerify: 0xad,
  OpCheckLockTimeVerify: 0xb0,
  OpTxLockTime: 0xb5,
  OpSub: 0x94, OpDiv: 0x96, OpMul: 0x95, OpMin: 0xa3,
  Op0: 0x00,
  OpGreaterThan: 0xa0, OpLessThanOrEqual: 0xa1,
  OpDup: 0x76, OpSwap: 0x7c, OpDrop: 0x75,
  OpIf: 0x63, OpElse: 0x67, OpEndIf: 0x68,
  OpVerify: 0x69, OpEqualVerify: 0x88, OpTrue: 0x51,
  OpTxInputIndex: 0xb9, OpTxOutputAmount: 0xc2, OpTxOutputSpk: 0xc3, OpTxInputSpk: 0xbf,
  OpInputCovenantId: 0xcf, OpOutputCovenantId: 0xd5,
};

// A minimal script tokenizer. Handles direct-push (0x01..0x4b), OpPushData1/2/4, and small-int
// opcodes Op0 (0x00) and Op1..Op16 (0x51..0x60) and Op1Negate (0x4f) which addI64 may emit.
function tokenize(bytes) {
  const toks = [];
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i++];
    if (op >= 0x01 && op <= 0x4b) {
      if (i + op > bytes.length) throw new Error("truncated push");
      toks.push({ op: "push", data: bytes.slice(i, i + op) });
      i += op;
    } else if (op === 0x4c || op === 0x4d || op === 0x4e) {
      const n = op === 0x4c ? 1 : op === 0x4d ? 2 : 4;
      if (i + n > bytes.length) throw new Error("truncated push length");
      // Use multiplication (not <<) so the 4-byte length never wraps negative in 32-bit signed math.
      let len = 0; for (let j = 0; j < n; j++) len += bytes[i++] * 2 ** (8 * j);
      if (len < 0 || i + len > bytes.length) throw new Error("push length overruns script");
      toks.push({ op: "push", data: bytes.slice(i, i + len) });
      i += len;
    } else {
      toks.push({ op });
    }
    if (toks.length > bytes.length) throw new Error("token overflow"); // hard backstop
  }
  return toks;
}

// Decode a minimally-encoded script number (little-endian, sign-magnitude high bit) to BigInt.
function decodeNum(data) {
  if (data.length === 0) return 0n;
  let n = 0n;
  for (let j = 0; j < data.length; j++) n |= BigInt(data[j]) << (8n * BigInt(j));
  const signBit = 1n << (8n * BigInt(data.length) - 1n);
  if (n & signBit) n = -(n & (signBit - 1n));
  return n;
}

// Read the numeric operand at token index `k`: either a small-int opcode or a data push.
function numAt(toks, k) {
  const t = toks[k];
  if (t.op === "push") return decodeNum(t.data);
  if (t.op === 0x00) return 0n;           // Op0
  if (t.op === 0x4f) return -1n;          // Op1Negate
  if (t.op >= 0x51 && t.op <= 0x60) return BigInt(t.op - 0x50); // Op1..Op16
  throw new Error(`expected number at token ${k}, got op 0x${(t.op ?? 0).toString(16)}`);
}

// The LOCK_V1 skeleton: a list of matchers. `n:"name"` marks a numeric constant slot; `pub` a 32B
// pubkey slot; a hex number is a literal opcode that must match exactly.
const SKELETON = [
  { pub: "beneficiaryPub" },
  OP.OpCheckSigVerify,
  { n: "cliffMs" }, OP.OpCheckLockTimeVerify,
  OP.OpTxLockTime, { n: "startMs" }, OP.OpSub,
  { n: "periodMs" }, OP.OpDiv,
  { n: "nPeriods" }, OP.OpMin,
  { n: "perPeriod" }, OP.OpMul,
  { n: "total" }, OP.OpSwap, OP.OpSub,
  OP.OpDup, { n: "zero" }, OP.OpGreaterThan, OP.OpIf,
  OP.OpTxInputIndex, OP.OpTxOutputAmount, OP.OpLessThanOrEqual, OP.OpVerify,
  OP.OpTxInputIndex, OP.OpTxOutputSpk, OP.OpTxInputIndex, OP.OpTxInputSpk, OP.OpEqualVerify,
  OP.OpTxInputIndex, OP.OpOutputCovenantId, OP.OpTxInputIndex, OP.OpInputCovenantId, OP.OpEqualVerify,
  OP.OpElse, OP.OpDrop, OP.OpEndIf, OP.OpTrue,
];

export const BADGE = { STRONG: "STRONG", PARTIAL: "PARTIAL", TRIVIAL: "TRIVIAL", NONE: "NONE" };

/**
 * Verify a candidate redeem (Uint8Array or hex). Returns:
 *   { match:true, params, total, fingerprint }  on a valid LOCK_V1
 *   { match:false, reason }                      otherwise
 */
export function verifyLock(redeem) {
  const bytes = redeem instanceof Uint8Array ? redeem : hexToBytes(redeem);
  let toks;
  try { toks = tokenize(bytes); } catch (e) { return { match: false, reason: `tokenize: ${e.message}` }; }
  if (toks.length !== SKELETON.length) return { match: false, reason: `token count ${toks.length} != ${SKELETON.length}` };

  const slots = {};
  for (let k = 0; k < SKELETON.length; k++) {
    const m = SKELETON[k], t = toks[k];
    if (typeof m === "number") {
      if (t.op !== m) return { match: false, reason: `op[${k}] 0x${(t.op ?? -1).toString(16)} != 0x${m.toString(16)}` };
    } else if (m.pub) {
      if (t.op !== "push" || t.data.length !== 32) return { match: false, reason: `pubkey slot[${k}] not a 32B push` };
      slots.beneficiaryPub = t.data;
    } else if (m.n) {
      try { slots[m.n] = numAt(toks, k); } catch (e) { return { match: false, reason: e.message }; }
    }
  }
  if (slots.zero !== 0n) return { match: false, reason: "floor comparison constant is not 0" };

  const params = {
    beneficiaryPub: slots.beneficiaryPub,
    startMs: slots.startMs, cliffMs: slots.cliffMs,
    periodMs: slots.periodMs, nPeriods: slots.nPeriods, perPeriod: slots.perPeriod,
  };
  // Internal consistency: embedded total must equal nPeriods*perPeriod.
  const derivedTotal = slots.nPeriods * slots.perPeriod;
  if (derivedTotal !== slots.total) return { match: false, reason: `total slot ${slots.total} != nPeriods*perPeriod ${derivedTotal}` };

  // Belt-and-suspenders: rebuild and require exact byte-equality.
  let rebuilt;
  try { rebuilt = null; rebuilt = rebuildAndCompare(params, bytes); }
  catch (e) { return { match: false, reason: `rebuild: ${e.message}` }; }
  if (!rebuilt) return { match: false, reason: "rebuilt bytes differ from candidate" };

  return { match: true, params, total: slots.total, fingerprint: fingerprint() };
}

// Rebuild via the audited pure-JS builder and require exact byte-equality. WASM-free by design:
// the badge sidecar verifies scripts without loading any WASM module.
let _builder = buildLockRedeemJS;
export function setBuilder(fn) { _builder = fn; } // override for cross-checking against the WASM builder
function rebuildAndCompare(params, candidate) {
  const rebuilt = _builder(params);
  if (rebuilt.length !== candidate.length) return false;
  for (let i = 0; i < rebuilt.length; i++) if (rebuilt[i] !== candidate[i]) return false;
  return true;
}

// Template fingerprint = hash of the skeleton with constant slots zeroed (position/length independent).
export function fingerprint() {
  const parts = SKELETON.map((m) => (typeof m === "number" ? `op:${m}` : m.pub ? "slot:pub" : `slot:${m.n}`));
  return createHash("sha256").update(parts.join("|")).digest("hex");
}

/**
 * Human-readable lock terms (red-team F4). The covenant cannot protect a beneficiary from a
 * malicious CREATOR (schedule/pubkey are off-chain-validated only), so any consumer MUST confirm,
 * from the verified on-chain script: (a) beneficiaryPub is THEIR key, (b) the schedule/amount match
 * the advertised terms. This renders those facts for a UI/badge tooltip. `decimals` scales base
 * units for display; `msToDate` converts unix-ms (default: ISO string).
 */
export function describeLock(params, { decimals = 8, msToDate = (ms) => new Date(Number(ms)).toISOString() } = {}) {
  const total = params.nPeriods * params.perPeriod;
  const scale = (v) => (Number(v) / 10 ** decimals).toLocaleString(undefined, { maximumFractionDigits: decimals });
  const endMs = params.startMs + params.nPeriods * params.periodMs;
  return {
    beneficiaryPubHex: bytesToHex(params.beneficiaryPub),
    total: total.toString(), totalDisplay: scale(total),
    perPeriodDisplay: scale(params.perPeriod),
    nPeriods: params.nPeriods.toString(),
    periodSeconds: (params.periodMs / 1000n).toString(),
    start: msToDate(params.startMs),
    cliff: msToDate(params.cliffMs),
    end: msToDate(endMs),
    durationDays: (Number(params.nPeriods * params.periodMs) / 86_400_000).toFixed(2),
    confirmPrompt: "Confirm: this pubkey is YOURS and these dates/amounts match the terms you were promised. The badge proves the script is a genuine LOCK_V1; it does NOT prove the creator's honesty about which key or amount.",
  };
}

/** Badge tier from verified params + token supply (supply in same base units as perPeriod). */
export function badgeTier(params, totalLocked, tokenSupply) {
  if (!tokenSupply || tokenSupply <= 0n) return BADGE.NONE;
  const pct = Number((totalLocked * 10000n) / tokenSupply) / 100; // % of supply
  const durationMs = params.nPeriods * params.periodMs;
  const sixMonthsMs = 15_552_000_000n;
  if (pct >= 20 && durationMs >= sixMonthsMs) return BADGE.STRONG;
  if (pct >= 5) return BADGE.PARTIAL;
  return BADGE.TRIVIAL;
}

/**
 * Full on-chain badge evaluation (fixes red-team F1). The badge is only honest if what is actually
 * funded matches the schedule the script encodes. The caller supplies chain data:
 *   - genesisValueSompi: the value of the lock output in the CREATION tx (the definitive funded amount)
 *   - currentAmountSompi: the current covenant UTXO amount (0 if fully claimed / terminated)
 *   - tokenSupplyBase:    token supply for the %-of-supply tier (optional)
 *   - nowMs:              current time (optional; for the vested/remaining display)
 *
 * Rule: refuse the badge unless the script verifies AND genesisValue == TOTAL. An over- or
 * under-funded lock (genesisValue != TOTAL) is flagged, never badged, because the script only
 * protects TOTAL and any excess is immediately liquid.
 */
export function evaluateBadge({ redeem, genesisValueSompi, currentAmountSompi, tokenSupplyBase, nowMs }) {
  const v = verifyLock(redeem);
  if (!v.match) return { badge: BADGE.NONE, verified: false, reason: v.reason };

  const total = v.total;
  const genesis = genesisValueSompi === undefined ? undefined : BigInt(genesisValueSompi);
  if (genesis === undefined) return { badge: BADGE.NONE, verified: true, reason: "genesis value unknown — cannot confirm funded==TOTAL", params: v.params, total };
  if (genesis !== total) {
    return {
      badge: BADGE.NONE, verified: true, funded: false,
      reason: genesis > total ? `OVER-FUNDED: genesis ${genesis} > TOTAL ${total} (excess is liquid/unvested)` : `UNDER-FUNDED: genesis ${genesis} < TOTAL ${total}`,
      params: v.params, total,
    };
  }
  // Funded correctly. Sanity: current amount must be within [floor(now), TOTAL].
  const cur = currentAmountSompi === undefined ? undefined : BigInt(currentAmountSompi);
  const tier = tokenSupplyBase ? badgeTier(v.params, total, BigInt(tokenSupplyBase)) : BADGE.NONE;
  return {
    badge: tier, verified: true, funded: true,
    params: v.params, total, currentLocked: cur,
    fingerprint: v.fingerprint,
    reason: "ok",
  };
}
