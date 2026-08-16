/**
 * Phase 0 lifecycle runner — TN10 ONLY.
 * Commands:
 *   node src/lifecycle.js gen                 — create + persist a test wallet
 *   node src/lifecycle.js balance            — show wallet UTXOs
 *   node src/lifecycle.js create             — create a short test lock (5 KAS, 2-min cliff, 10x1-min periods)
 *   node src/lifecycle.js status             — show lock UTXO + vested/claimable math
 *   node src/lifecycle.js claim              — partial claim (max claimable now)
 *   node src/lifecycle.js claim --amount N   — claim N sompi less than max
 * State: ./state.json (testnet wallet — throwaway, fine to persist in plaintext).
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadKaspa } from "@kronsdk/kron-sdk/wasm";
import * as sdk from "@kronsdk/kron-sdk";
import { buildLockRedeem, lockSpk, lockAddress, vestedAt, continuationFloor, bytesToHex, hexToBytes } from "./lockv1.js";

const NETWORK = "testnet-10";
const STATE = fileURLToPath(new URL("../state.json", import.meta.url));
const st = existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : {};
const save = () => writeFileSync(STATE, JSON.stringify(st, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2));

const cmd = process.argv[2] ?? "status";
const k = await loadKaspa();

function wallet() {
  if (!st.priv) throw new Error("no wallet — run: node src/lifecycle.js gen");
  const priv = new k.PrivateKey(st.priv);
  const pub = priv.toPublicKey();
  return { priv, pub, xonly: hexToBytes(pub.toXOnlyPublicKey().toString()), address: pub.toAddress(NETWORK).toString() };
}

function lockParams() {
  if (!st.lock) throw new Error("no lock — run create first");
  const p = st.lock.params;
  return {
    beneficiaryPub: hexToBytes(p.beneficiaryPub),
    startMs: BigInt(p.startMs), cliffMs: BigInt(p.cliffMs),
    periodMs: BigInt(p.periodMs), nPeriods: BigInt(p.nPeriods), perPeriod: BigInt(p.perPeriod),
  };
}

// Sign P2PK funding inputs. NOTE: with vendored kaspa WASM 2.0.1, createInputSignature already
// returns the COMPLETE pushed sig element (push-opcode + 64B schnorr + 1B sighash = 66B), which is
// byte-identical to the on-chain signatureScript. The SDK's signFundingInputs wraps it again in
// addData() → double push → "malformed signature". So we assign the result directly.
function signFunding(tx, priv, idxs) {
  const sigs = idxs.map((i) => k.createInputSignature(tx, i, priv, k.SighashType.All));
  const ins = tx.inputs;
  idxs.forEach((i, j) => { ins[i].signatureScript = sigs[j]; });
  tx.inputs = ins;
}

async function rpc() {
  const client = new k.RpcClient({ resolver: new k.Resolver(), networkId: NETWORK });
  await client.connect();
  const info = await client.getServerInfo();
  console.log(`[rpc] connected: ${client.url} synced=${info.isSynced} virtualDaa=${info.virtualDaaScore}`);
  return client;
}

async function utxos(client, address) {
  const { entries } = await client.getUtxosByAddresses([address]);
  return entries;
}

if (cmd === "gen") {
  if (st.priv) { console.log("wallet exists:", wallet().address); process.exit(0); }
  const { randomBytes } = await import("node:crypto");
  const priv = new k.PrivateKey(randomBytes(32).toString("hex"));
  st.priv = priv.toString();
  save();
  console.log("new TN10 wallet:", wallet().address);
  console.log("fund it via a TN10 faucet, then run: node src/lifecycle.js balance");
  process.exit(0);
}

const w = wallet();

if (cmd === "balance") {
  const client = await rpc();
  const es = await utxos(client, w.address);
  let sum = 0n;
  for (const e of es) sum += BigInt(e.amount ?? e.entry?.amount ?? 0);
  console.log(`address: ${w.address}`);
  console.log(`utxos: ${es.length}  total: ${Number(sum) / 1e8} KAS`);
  client.disconnect();
  process.exit(0);
}

if (cmd === "create") {
  if (st.lock?.covid) throw new Error("lock already exists in state.json — delete it to start over");
  const now = BigInt(Date.now());
  const params = {
    beneficiaryPub: w.xonly,
    startMs: now,
    cliffMs: now + 120_000n,      // 2-minute cliff
    periodMs: 60_000n,            // 1-minute periods (spec floor)
    nPeriods: 10n,
    perPeriod: 50_000_000n,       // 0.5 KAS => 5 KAS total, fully vested in 10 min
  };
  const redeem = buildLockRedeem(k, params);
  const spk = lockSpk(k, redeem);
  const total = params.nPeriods * params.perPeriod;

  const client = await rpc();
  const es = await utxos(client, w.address);
  if (!es.length) throw new Error("no funding UTXOs — hit a TN10 faucet first");

  // Deterministic genesis: use exactly one funding entry so it is input 0.
  const funding = es.sort((a, b) => Number(BigInt(b.amount ?? b.entry?.amount) - BigInt(a.amount ?? a.entry?.amount)))[0];
  const fOutpoint = funding.outpoint ?? funding.entry?.outpoint;
  const genesisOutpoint = { transactionId: fOutpoint.transactionId, index: fOutpoint.index };

  // F1 invariant: the covenant only protects TOTAL (a script constant), never its own balance, so
  // the genesis output value MUST equal TOTAL exactly — any excess would be immediately liquid.
  if (total !== params.nPeriods * params.perPeriod) throw new Error("genesis value must equal TOTAL (F1)");
  // Lock output will be output 0; compute its KIP-20 genesis covenant id.
  const lockOutput = { value: total, scriptPublicKey: spk };
  const covid = sdk.genesis.genesisCovenantId(k, genesisOutpoint, [{ index: 0, value: total, scriptPublicKey: spk }]);
  console.log("[create] genesis covid:", covid);

  const spend = {
    kind: "init",
    inputs: [], // no covenant inputs at creation
    outputs: [{ ...lockOutput, role: "lock", binding: { covid, authorizingInput: 0 } }],
    economics: {},
  };
  let asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: 10_000n });
  const fee = sdk.spend.estimateNativeFee(k, NETWORK, asm, 100);
  asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: fee });
  signFunding(asm.transaction, w.priv, asm.fundingInputIndexes);
  const { transactionId } = await client.submitTransaction({ transaction: asm.transaction });
  console.log("[create] submitted:", transactionId);

  st.lock = {
    covid,
    redeem: bytesToHex(redeem),
    address: lockAddress(k, redeem, NETWORK),
    createTx: transactionId,
    params: { ...params, beneficiaryPub: bytesToHex(params.beneficiaryPub) },
    total: total.toString(),
    claims: [],
  };
  save();
  console.log("[create] lock address:", st.lock.address, "total:", Number(total) / 1e8, "KAS");
  client.disconnect();
  process.exit(0);
}

if (cmd === "status") {
  const p = lockParams();
  const client = await rpc();
  const es = await utxos(client, st.lock.address);
  const now = BigInt(Date.now());
  const total = p.nPeriods * p.perPeriod;
  let remaining = 0n;
  for (const e of es) remaining += BigInt(e.amount ?? e.entry?.amount ?? 0);
  const vested = vestedAt(p, now);
  const floor = continuationFloor(p, now);
  console.log(`lock: ${st.lock.address}`);
  console.log(`covid: ${st.lock.covid}`);
  console.log(`utxos: ${es.length} remaining: ${Number(remaining) / 1e8} KAS / total ${Number(total) / 1e8}`);
  console.log(`vested: ${Number(vested) / 1e8} KAS  floor: ${Number(floor) / 1e8}  claimable: ${Number(remaining - floor) / 1e8}`);
  client.disconnect();
  process.exit(0);
}

if (cmd === "claim") {
  const p = lockParams();
  const redeem = hexToBytes(st.lock.redeem);
  const spk = lockSpk(k, redeem);
  const client = await rpc();
  const es = await utxos(client, st.lock.address);
  if (!es.length) throw new Error("no lock UTXO found");
  const lockUtxo = es[0];
  const lOutpoint = lockUtxo.outpoint ?? lockUtxo.entry?.outpoint;
  const lockAmount = BigInt(lockUtxo.amount ?? lockUtxo.entry?.amount);

  // lock_time must satisfy BOTH: (a) consensus finalization — tx.lock_time < node past-median-time
  // (which lags wall clock, ~130s on TN10), and (b) the script CLTV — tx.lock_time >= cliffMs.
  // Anchor to the node's reported pastMedianTime (minus a safety margin, since median only moves
  // forward between our read and mempool validation).
  const dag = await client.getBlockDagInfo();
  const medianMs = BigInt(dag.pastMedianTime);
  const lockTimeMs = medianMs - 2_000n;
  if (lockTimeMs < p.cliffMs)
    throw new Error(`cliff not matured in median-time yet: medianTime=${medianMs} < cliffMs=${p.cliffMs} (wait ~${Number(p.cliffMs - lockTimeMs) / 1000}s)`);
  const floor = continuationFloor(p, lockTimeMs);
  const claimable = lockAmount - floor;
  if (claimable <= 0n) throw new Error(`nothing claimable yet at lockTime=${lockTimeMs} (floor=${floor})`);
  console.log(`[claim] medianTime=${medianMs} lockTime=${lockTimeMs} lockAmount=${lockAmount} floor=${floor} claimable=${claimable}`);

  const fundingAll = await utxos(client, w.address);
  if (!fundingAll.length) throw new Error("no fee-funding UTXO in wallet");
  const funding = fundingAll[0];

  const finalClaim = floor === 0n;
  const covInput = {
    transactionId: lOutpoint.transactionId, index: lOutpoint.index, value: lockAmount,
    scriptPublicKey: spk,
    // placeholder sig for size estimation; replaced after lockTime/sequence are set
    signatureScript: k.payToScriptHashSignatureScript(redeem, "41" + "00".repeat(65)),
    redeem, role: "pool",
  };
  const outputs = [];
  if (!finalClaim) {
    // continuation at output[own input index] = 0 with same spk + same covid (KIP-20 continuation)
    outputs.push({ value: floor, scriptPublicKey: spk, role: "lock-cont", binding: { covid: st.lock.covid, authorizingInput: 0 } });
  }
  // claimed funds to beneficiary wallet (index 1, or 0 on final claim — unconstrained by script)
  outputs.push({ value: claimable, scriptPublicKey: k.payToAddressScript(w.address), role: "recipient" });

  const spend = { kind: finalClaim ? "claimFinal" : "claim", inputs: [covInput], outputs, economics: {} };
  const build = (fee) => sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: fee });
  let asm = build(10_000n);
  const fee = sdk.spend.estimateNativeFee(k, NETWORK, asm, 100);
  asm = build(fee);

  const tx = asm.transaction;
  tx.lockTime = lockTimeMs;                     // Time-type (>= 500e9): matches CLTV pin
  const inputs = tx.inputs;                     // ensure covenant input sequence is NOT final
  console.log("[claim] input0 sequence (pre):", inputs[0].sequence?.toString?.());
  inputs[0].sequence = 0n;

  // Real signature over the final tx shape, then swap into the P2SH sigscript.
  // F2 (HARD REQUIREMENT): claims MUST be signed SIGHASH_ALL. The covenant cannot constrain the
  // sighash type; SINGLE/NONE would leave the beneficiary's payout outputs uncommitted and a mempool
  // observer could rewrite them. Never expose any other type in a claim signer.
  const CLAIM_SIGHASH = k.SighashType.All;
  const sig = k.createInputSignature(tx, 0, w.priv, CLAIM_SIGHASH);
  inputs[0].signatureScript = k.payToScriptHashSignatureScript(redeem, sig);
  signFunding(tx, w.priv, asm.fundingInputIndexes);

  const { transactionId } = await client.submitTransaction({ transaction: tx });
  console.log(`[claim] submitted ${finalClaim ? "FINAL" : "partial"} claim:`, transactionId);
  st.lock.claims.push({ tx: transactionId, lockTimeMs: lockTimeMs.toString(), claimed: claimable.toString(), final: finalClaim });
  save();
  client.disconnect();
  process.exit(0);
}

console.error("unknown command:", cmd);
process.exit(1);
