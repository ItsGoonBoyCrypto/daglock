/**
 * DagLock MAINNET admin tool — owner-operated, REAL KAS. Use to validate DagLock on Kaspa mainnet
 * before any public wiring. Safety by design:
 *   - dry-run by default; nothing is broadcast without the literal `--confirm` flag
 *   - hard cap on lock size (DAGLOCK_MAX_KAS, default 25) so a fat-finger can't lock a fortune
 *   - full parameter echo (human dates via describeLock) before every broadcast
 *   - reuses the AUDITED builder (lockv1.js) + verifier (verify.js) unchanged
 *
 * Wallet: mainnet_state.json (a dedicated admin wallet — fund it with a SMALL amount).
 *
 * Commands:
 *   gen                                   create/persist the admin wallet, print address
 *   balance                               show wallet balance
 *   create <KAS> <cliffMin> <perMin> <N> [--confirm]   build a lock (KAS total, cliff mins, period mins, N periods)
 *   status                                on-chain lock state + vested/floor/claimable
 *   verify                                run evaluateBadge against the on-chain genesis value + describeLock
 *   claim [--confirm]                     claim everything claimable now (auto partial/final)
 *
 * Typical mainnet smoke (see MAINNET_TEST_SPEC.md): gen → fund → create 2 5 5 4 --confirm →
 * verify → status → (wait) claim --confirm ×N → status shows 0.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { loadKaspa } from "@kronsdk/kron-sdk/wasm";
import * as sdk from "@kronsdk/kron-sdk";
import { buildLockRedeem, lockSpk, lockAddress, continuationFloor, vestedAt, hexToBytes, bytesToHex } from "./lockv1.js";
import { evaluateBadge, describeLock } from "./verify.js";

const NETWORK = "mainnet";
const MAX_KAS = BigInt(Math.floor(Number(process.env.DAGLOCK_MAX_KAS ?? "25")));
const SOMPI = 100_000_000n;
const STATE = fileURLToPath(new URL("../mainnet_state.json", import.meta.url));
const st = existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : {};
const save = () => writeFileSync(STATE, JSON.stringify(st, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
const argv = process.argv.slice(2);
const cmd = argv[0] ?? "status";
const CONFIRM = argv.includes("--confirm");
const kas = (s) => (Number(s) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });

console.log("╔══════════════════════════════════════════════════════╗");
console.log("║  DagLock MAINNET admin — REAL KAS. Owner use only.    ║");
console.log("╚══════════════════════════════════════════════════════╝");

const k = await loadKaspa();
function wallet() {
  if (!st.priv) throw new Error("no wallet — run: node src/mainnet_admin.js gen");
  const priv = new k.PrivateKey(st.priv);
  const pub = priv.toPublicKey();
  return { priv, pub, xonly: hexToBytes(pub.toXOnlyPublicKey().toString()), address: pub.toAddress(NETWORK).toString() };
}
function signFunding(tx, idxs, sk) {
  const sigs = idxs.map((i) => k.createInputSignature(tx, i, sk, k.SighashType.All));
  const ins = tx.inputs; idxs.forEach((i, j) => { ins[i].signatureScript = sigs[j]; }); tx.inputs = ins;
}

if (cmd === "gen") {
  if (st.priv) { console.log("wallet exists:", wallet().address); process.exit(0); }
  st.priv = new k.PrivateKey(randomBytes(32).toString("hex")).toString();
  save();
  console.log("NEW MAINNET admin wallet:", wallet().address);
  console.log("⚠  Fund with a SMALL amount only (a few KAS). This file (mainnet_state.json) holds the key in plaintext — treat as a burner.");
  process.exit(0);
}

const w = wallet();
const client = new k.RpcClient({ resolver: new k.Resolver(), networkId: NETWORK });
await client.connect();
const info = await client.getServerInfo();
console.log(`[rpc] ${client.url} synced=${info.isSynced}`);
if (!info.isSynced) { console.log("node not synced — aborting"); process.exit(1); }
const utxos = async (a) => (await client.getUtxosByAddresses([a])).entries;

if (cmd === "balance") {
  const es = await utxos(w.address);
  let sum = 0n; for (const e of es) sum += BigInt(e.amount);
  console.log(`address: ${w.address}\nutxos: ${es.length}  balance: ${kas(sum)} KAS`);
  client.disconnect(); process.exit(0);
}

if (cmd === "create") {
  if (st.lock?.covid) throw new Error("a lock already exists in mainnet_state.json — finish/clear it first");
  const [, totalKasArg, cliffMinArg, perMinArg, nArg] = argv;
  if (!totalKasArg || !cliffMinArg || !perMinArg || !nArg) throw new Error("usage: create <totalKAS> <cliffMins> <periodMins> <nPeriods> [--confirm]");
  const perPeriodKas = Number(totalKasArg) / Number(nArg);
  const params = {
    beneficiaryPub: w.xonly,
    startMs: BigInt(Date.now()),
    cliffMs: BigInt(Date.now()) + BigInt(Math.round(Number(cliffMinArg) * 60_000)),
    periodMs: BigInt(Math.round(Number(perMinArg) * 60_000)),
    nPeriods: BigInt(nArg),
    perPeriod: BigInt(Math.round(perPeriodKas * 1e8)),
  };
  const total = params.nPeriods * params.perPeriod;
  if (total !== BigInt(Math.round(Number(totalKasArg) * 1e8))) throw new Error(`total ${kas(total)} != ${totalKasArg} KAS — pick nPeriods that divides the total evenly`);
  if (total > MAX_KAS * SOMPI) throw new Error(`SAFETY: total ${kas(total)} KAS exceeds cap ${MAX_KAS} KAS (raise DAGLOCK_MAX_KAS to override deliberately)`);

  const redeem = buildLockRedeem(k, params);
  const spk = lockSpk(k, redeem);
  const desc = describeLock(params);
  console.log("\n── LOCK TO BE CREATED (irreversible once broadcast) ──");
  console.log(`  total:       ${kas(total)} KAS  (${desc.nPeriods} periods × ${kas(params.perPeriod)} KAS)`);
  console.log(`  beneficiary: ${w.address}`);
  console.log(`  pubkey:      ${desc.beneficiaryPubHex}`);
  console.log(`  start:       ${desc.start}`);
  console.log(`  cliff:       ${desc.cliff}`);
  console.log(`  end:         ${desc.end}  (${desc.durationDays} days)`);
  console.log(`  period:      ${desc.periodSeconds}s`);
  console.log(`  lock addr:   ${lockAddress(k, redeem, NETWORK)}`);

  if (!CONFIRM) { console.log("\n(dry-run — re-run with --confirm to broadcast)"); client.disconnect(); process.exit(0); }

  const es = (await utxos(w.address)).sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
  if (!es.length) throw new Error("no funding UTXO — fund the admin wallet first");
  const funding = es[0];
  const go = { transactionId: funding.outpoint.transactionId, index: funding.outpoint.index };
  const covid = sdk.genesis.genesisCovenantId(k, go, [{ index: 0, value: total, scriptPublicKey: spk }]);
  // F1: genesis value MUST equal TOTAL exactly.
  const spend = { kind: "init", inputs: [], outputs: [{ value: total, scriptPublicKey: spk, role: "lock", binding: { covid, authorizingInput: 0 } }], economics: {} };
  let asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: 20_000n });
  const fee = sdk.spend.estimateNativeFee(k, NETWORK, asm, 100);
  asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: fee });
  signFunding(asm.transaction, asm.fundingInputIndexes, w.priv);
  const { transactionId } = await client.submitTransaction({ transaction: asm.transaction });
  st.lock = { covid, redeem: bytesToHex(redeem), address: lockAddress(k, redeem, NETWORK), createTx: transactionId, genesisValue: total.toString(), params: { ...params, beneficiaryPub: bytesToHex(params.beneficiaryPub) }, total: total.toString(), claims: [] };
  save();
  console.log(`\n✅ BROADCAST. lock ${st.lock.address}  tx ${transactionId}`);
  client.disconnect(); process.exit(0);
}

// lock-scoped commands need a stored lock
if (!st.lock) { console.log("no lock in mainnet_state.json — run create first"); process.exit(1); }
const P = st.lock.params;
const p = { beneficiaryPub: hexToBytes(P.beneficiaryPub), startMs: BigInt(P.startMs), cliffMs: BigInt(P.cliffMs), periodMs: BigInt(P.periodMs), nPeriods: BigInt(P.nPeriods), perPeriod: BigInt(P.perPeriod) };
const redeem = hexToBytes(st.lock.redeem);
const spk = lockSpk(k, redeem);
const total = p.nPeriods * p.perPeriod;

if (cmd === "verify") {
  const es = await utxos(st.lock.address);
  const current = es.length ? BigInt(es[0].amount) : 0n;
  const badge = evaluateBadge({ redeem, genesisValueSompi: BigInt(st.lock.genesisValue), currentAmountSompi: current });
  const desc = describeLock(p);
  console.log(`\nverified: ${badge.verified}  funded: ${badge.funded}  reason: ${badge.reason}`);
  console.log(`fingerprint: ${badge.fingerprint ?? "-"}`);
  console.log(`terms: ${desc.totalDisplay} KAS over ${desc.nPeriods}×${desc.periodSeconds}s, cliff ${desc.cliff}, ends ${desc.end}`);
  console.log(`beneficiary pubkey: ${desc.beneficiaryPubHex}`);
  console.log(`current on-chain locked: ${kas(current)} KAS`);
  client.disconnect(); process.exit(badge.funded ? 0 : 1);
}

if (cmd === "status") {
  const es = await utxos(st.lock.address);
  const remaining = es.length ? BigInt(es[0].amount) : 0n;
  const dag = await client.getBlockDagInfo();
  const median = BigInt(dag.pastMedianTime);
  const floor = continuationFloor(p, median);
  console.log(`\nlock: ${st.lock.address}\ncovid: ${st.lock.covid}`);
  console.log(`remaining: ${kas(remaining)} / ${kas(total)} KAS   utxos: ${es.length}`);
  console.log(`median-time: ${new Date(Number(median)).toISOString()}`);
  console.log(`vested(@median): ${kas(vestedAt(p, median))}  floor: ${kas(floor)}  claimable: ${kas(remaining - floor > 0n ? remaining - floor : 0n)}`);
  client.disconnect(); process.exit(0);
}

if (cmd === "claim") {
  const es = await utxos(st.lock.address);
  if (!es.length) { console.log("no lock UTXO — already fully claimed?"); process.exit(0); }
  const lu = es[0]; const lockAmount = BigInt(lu.amount);
  const dag = await client.getBlockDagInfo();
  const lockTimeMs = BigInt(dag.pastMedianTime) - 2_000n;   // anchor to median-time (must be < PMT)
  if (lockTimeMs < p.cliffMs) throw new Error(`cliff not matured in median-time yet (need +${Number(p.cliffMs - lockTimeMs) / 1000}s)`);
  const floor = continuationFloor(p, lockTimeMs);
  const claimable = lockAmount - floor;
  if (claimable <= 0n) throw new Error(`nothing claimable yet (floor ${kas(floor)} == balance ${kas(lockAmount)})`);
  const finalClaim = floor === 0n;
  console.log(`\nclaim: ${finalClaim ? "FINAL" : "partial"}  claimable=${kas(claimable)} KAS  re-lock floor=${kas(floor)} KAS`);
  if (!CONFIRM) { console.log("(dry-run — re-run with --confirm to broadcast)"); client.disconnect(); process.exit(0); }

  const funding = (await utxos(w.address))[0];
  if (!funding) throw new Error("no fee-funding UTXO in wallet");
  const covInput = { transactionId: lu.outpoint.transactionId, index: lu.outpoint.index, value: lockAmount, scriptPublicKey: spk, signatureScript: k.payToScriptHashSignatureScript(redeem, "41" + "00".repeat(65)), redeem, role: "pool" };
  const outputs = [];
  if (!finalClaim) outputs.push({ value: floor, scriptPublicKey: spk, role: "cont", binding: { covid: st.lock.covid, authorizingInput: 0 } });
  outputs.push({ value: claimable, scriptPublicKey: k.payToAddressScript(w.address), role: "pay" });
  const spend = { kind: finalClaim ? "claimFinal" : "claim", inputs: [covInput], outputs, economics: {} };
  const build = (feeV) => sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: feeV });
  let asm = build(10_000n);
  asm = build(sdk.spend.estimateNativeFee(k, NETWORK, asm, 100));
  const tx = asm.transaction;
  tx.lockTime = lockTimeMs;
  const ins = tx.inputs; ins[0].sequence = 0n; tx.inputs = ins;
  const sig = k.createInputSignature(tx, 0, w.priv, k.SighashType.All); // F2: SIGHASH_ALL only
  const ins2 = tx.inputs; ins2[0].signatureScript = k.payToScriptHashSignatureScript(redeem, sig); tx.inputs = ins2;
  signFunding(tx, asm.fundingInputIndexes, w.priv);
  const { transactionId } = await client.submitTransaction({ transaction: tx });
  st.lock.claims.push({ tx: transactionId, claimed: claimable.toString(), final: finalClaim });
  save();
  console.log(`✅ ${finalClaim ? "FINAL" : "partial"} claim broadcast: ${transactionId}`);
  client.disconnect(); process.exit(0);
}

console.log("unknown command:", cmd);
process.exit(1);
