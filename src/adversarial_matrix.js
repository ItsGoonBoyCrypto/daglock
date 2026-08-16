/**
 * On-chain adversarial matrix — TN10, real consensus interpreter.
 * Fires a battery of malicious claims at ONE live lock UTXO. Every malicious claim MUST be rejected
 * (a rejected tx doesn't consume the UTXO, so we reuse it), then an honest claim MUST be accepted.
 *
 *   node src/adversarial_matrix.js create   -> creates a fresh lock (5 TKAS, 20x60s, 2min cliff), saves advstate.json
 *   node src/adversarial_matrix.js run       -> runs the battery + honest control (run after ~5 min, while floor>0)
 *
 * Cases (all must REJECT): over-claim, wrong continuation spk, missing continuation, third-party
 * signature, wrong covid, continuation at wrong output index, lock_time<cliff (CLTV).
 * Control (must ACCEPT): honest partial claim.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { loadKaspa } from "@kronsdk/kron-sdk/wasm";
import * as sdk from "@kronsdk/kron-sdk";
import { buildLockRedeem, lockSpk, lockAddress, continuationFloor, hexToBytes, bytesToHex } from "./lockv1.js";

const NETWORK = "testnet-10";
const MAIN = JSON.parse(readFileSync(fileURLToPath(new URL("../state.json", import.meta.url)), "utf8"));
const ADV = fileURLToPath(new URL("../advstate.json", import.meta.url));
const k = await loadKaspa();
const priv = new k.PrivateKey(MAIN.priv);
const pub = priv.toPublicKey();
const address = pub.toAddress(NETWORK).toString();
const otherPriv = new k.PrivateKey(randomBytes(32).toString("hex")); // a non-beneficiary key

const cmd = process.argv[2] ?? "run";
const client = new k.RpcClient({ resolver: new k.Resolver(), networkId: NETWORK });
await client.connect();
const utxos = async (a) => (await client.getUtxosByAddresses([a])).entries;
function signFunding(tx, idxs, sk = priv) {
  const sigs = idxs.map((i) => k.createInputSignature(tx, i, sk, k.SighashType.All));
  const ins = tx.inputs; idxs.forEach((i, j) => { ins[i].signatureScript = sigs[j]; }); tx.inputs = ins;
}

if (cmd === "create") {
  const now = BigInt(Date.now());
  const params = { beneficiaryPub: hexToBytes(pub.toXOnlyPublicKey().toString()), startMs: now, cliffMs: now + 120_000n, periodMs: 60_000n, nPeriods: 20n, perPeriod: 25_000_000n };
  const total = params.nPeriods * params.perPeriod;
  const redeem = buildLockRedeem(k, params);
  const spk = lockSpk(k, redeem);
  const es = (await utxos(address)).sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
  const funding = es[0];
  const go = { transactionId: funding.outpoint.transactionId, index: funding.outpoint.index };
  const covid = sdk.genesis.genesisCovenantId(k, go, [{ index: 0, value: total, scriptPublicKey: spk }]);
  const spend = { kind: "init", inputs: [], outputs: [{ value: total, scriptPublicKey: spk, role: "lock", binding: { covid, authorizingInput: 0 } }], economics: {} };
  let asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: address, networkFee: 20_000n });
  const fee = sdk.spend.estimateNativeFee(k, NETWORK, asm, 100);
  asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: address, networkFee: fee });
  signFunding(asm.transaction, asm.fundingInputIndexes);
  const { transactionId } = await client.submitTransaction({ transaction: asm.transaction });
  const bi = (_key, v) => (typeof v === "bigint" ? v.toString() : v);
  writeFileSync(ADV, JSON.stringify({ covid, redeem: bytesToHex(redeem), address: lockAddress(k, redeem, NETWORK), params: { ...params, beneficiaryPub: bytesToHex(params.beneficiaryPub) }, total: total.toString(), createTx: transactionId }, bi, 2));
  console.log(`[create] adversarial lock ${lockAddress(k, redeem, NETWORK)} total=${Number(total) / 1e8} KAS tx=${transactionId}`);
  client.disconnect();
  process.exit(0);
}

// ---- run the battery ----
const st = JSON.parse(readFileSync(ADV, "utf8"));
const p = { beneficiaryPub: hexToBytes(st.params.beneficiaryPub), startMs: BigInt(st.params.startMs), cliffMs: BigInt(st.params.cliffMs), periodMs: BigInt(st.params.periodMs), nPeriods: BigInt(st.params.nPeriods), perPeriod: BigInt(st.params.perPeriod) };
const redeem = hexToBytes(st.redeem);
const spk = lockSpk(k, redeem);
const wrongSpk = k.payToScriptHashScript(hexToBytes("51")); // OpTrue P2SH
const wrongCovid = "11".repeat(32);

const dag = await client.getBlockDagInfo();
const median = BigInt(dag.pastMedianTime);
const lockTimeMs = median - 2_000n;
const floor = continuationFloor(p, lockTimeMs);
const lockUtxos = await utxos(st.address);
if (!lockUtxos.length) { console.log("no lock UTXO (already claimed?) — re-create"); process.exit(1); }
const lu = lockUtxos[0];
const lockAmount = BigInt(lu.amount);
const fullVest = p.startMs + p.nPeriods * p.periodMs;
console.log(`[matrix] median=${median} lockTime=${lockTimeMs} floor=${Number(floor) / 1e8} lockAmount=${Number(lockAmount) / 1e8} vested? ${median >= p.cliffMs} fullVest@${fullVest}`);
if (floor <= 0n) { console.log("floor==0 (fully vested) — continuation-branch cases inactive; re-create a longer lock"); process.exit(1); }
if (median < p.cliffMs) { console.log(`cliff not matured in median yet (need +${Number(p.cliffMs - median) / 1000}s)`); process.exit(1); }

// Build a claim tx with configurable perturbations. Returns the assembled+signed tx.
async function buildClaim(o = {}) {
  const funding = (await utxos(address))[0];
  const contValue = o.contValue ?? floor;
  const contSpk = o.contSpk ?? spk;
  const contCovid = o.contCovid ?? st.covid;
  const contIndex = o.contIndex ?? 0;
  const includeCont = o.includeCont ?? true;
  const lt = o.lockTimeMs ?? lockTimeMs;
  const signer = o.signer ?? priv;
  const payout = lockAmount - (includeCont ? contValue : 0n);
  const outs = [];
  const contOut = { value: contValue, scriptPublicKey: contSpk, role: "cont", binding: { covid: contCovid, authorizingInput: 0 } };
  const payOut = { value: payout > 0n ? payout : 1n, scriptPublicKey: k.payToAddressScript(address), role: "pay" };
  if (!includeCont) { outs.push(payOut); }
  else if (contIndex === 0) { outs.push(contOut, payOut); }
  else { outs.push(payOut, contOut); } // continuation at index 1 (wrong)
  const covInput = { transactionId: lu.outpoint.transactionId, index: lu.outpoint.index, value: lockAmount, scriptPublicKey: spk, signatureScript: k.payToScriptHashSignatureScript(redeem, "41" + "00".repeat(65)), redeem, role: "pool" };
  const spend = { kind: "claim", inputs: [covInput], outputs: outs, economics: {} };
  let asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: address, networkFee: 10_000n });
  const fee = sdk.spend.estimateNativeFee(k, NETWORK, asm, 100);
  asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: address, networkFee: fee });
  const tx = asm.transaction;
  tx.lockTime = lt;
  const ins = tx.inputs; ins[0].sequence = 0n; tx.inputs = ins;
  const sig = k.createInputSignature(tx, 0, signer, k.SighashType.All);
  const ins2 = tx.inputs; ins2[0].signatureScript = k.payToScriptHashSignatureScript(redeem, sig); tx.inputs = ins2;
  signFunding(tx, asm.fundingInputIndexes);
  return tx;
}

async function expectReject(name, opts) {
  try { const tx = await buildClaim(opts); await client.submitTransaction({ transaction: tx }); return { name, ok: false, msg: "ACCEPTED (should reject!)" }; }
  catch (e) { return { name, ok: true, msg: String(e.message || e).split("->").pop().trim().slice(0, 70) }; }
}

const results = [];
results.push(await expectReject("over-claim (cont < floor)", { contValue: floor - 25_000_000n }));
results.push(await expectReject("wrong continuation spk", { contSpk: wrongSpk }));
results.push(await expectReject("missing continuation", { includeCont: false }));
results.push(await expectReject("third-party signature", { signer: otherPriv }));
results.push(await expectReject("wrong covid on continuation", { contCovid: wrongCovid }));
results.push(await expectReject("continuation at wrong index (1)", { contIndex: 1 }));
results.push(await expectReject("lock_time < cliff (CLTV)", { lockTimeMs: p.cliffMs - 1_000n }));

let pass = results.every((r) => r.ok);
for (const r of results) console.log(`  ${r.ok ? "✅ REJECTED" : "❌ " + r.msg} — ${r.name}${r.ok ? ` (${r.msg})` : ""}`);

// Honest control — must ACCEPT (consumes the UTXO).
try {
  const tx = await buildClaim({}); // honest: cont=floor at index 0, beneficiary sig, valid lock_time
  const { transactionId } = await client.submitTransaction({ transaction: tx });
  console.log(`  ✅ ACCEPTED — honest control claim (tx ${transactionId.slice(0, 16)}…)`);
} catch (e) { pass = false; console.log(`  ❌ honest control REJECTED: ${String(e.message || e).split("->").pop().trim().slice(0, 80)}`); }

console.log(pass ? "\n✅ ADVERSARIAL MATRIX PASSED — all attacks rejected, honest claim accepted" : "\n❌ MATRIX FAILURE");
client.disconnect();
process.exit(pass ? 0 : 1);
