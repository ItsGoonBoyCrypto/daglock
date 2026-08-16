/**
 * Adversarial over-claim — MUST be rejected by consensus.
 * Builds a claim that underfunds the continuation output by `steal` sompi (i.e. tries to take
 * more than vested). The LOCK_V1 script asserts out[i].amount >= floor via OpLessThanOrEqual+OpVerify,
 * so the node must reject it. A SUCCESS here would be a critical finding.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadKaspa } from "@kronsdk/kron-sdk/wasm";
import * as sdk from "@kronsdk/kron-sdk";
import { buildLockRedeem, lockSpk, continuationFloor, hexToBytes } from "./lockv1.js";

const NETWORK = "testnet-10";
const STATE = fileURLToPath(new URL("../state.json", import.meta.url));
const st = JSON.parse(readFileSync(STATE, "utf8"));
const k = await loadKaspa();
const priv = new k.PrivateKey(st.priv);
const w = { priv, address: priv.toPublicKey().toAddress(NETWORK).toString() };
const STEAL = BigInt(process.argv[2] ?? "50000000"); // 0.5 KAS over-claim by default

const p = {
  beneficiaryPub: hexToBytes(st.lock.params.beneficiaryPub),
  startMs: BigInt(st.lock.params.startMs), cliffMs: BigInt(st.lock.params.cliffMs),
  periodMs: BigInt(st.lock.params.periodMs), nPeriods: BigInt(st.lock.params.nPeriods),
  perPeriod: BigInt(st.lock.params.perPeriod),
};
const redeem = hexToBytes(st.lock.redeem);
const spk = lockSpk(k, redeem);

const client = new k.RpcClient({ resolver: new k.Resolver(), networkId: NETWORK });
await client.connect();
const es = (await client.getUtxosByAddresses([st.lock.address])).entries;
const lockUtxo = es[0];
const lOutpoint = lockUtxo.outpoint;
const lockAmount = BigInt(lockUtxo.amount);

const dag = await client.getBlockDagInfo();
const lockTimeMs = BigInt(dag.pastMedianTime) - 2_000n;
const floor = continuationFloor(p, lockTimeMs);
// Honest continuation would be `floor`. We underfund it by STEAL and pocket the difference.
const badCont = floor - STEAL;
if (badCont < 0n) throw new Error("steal exceeds floor; pick a smaller amount");
const stolen = lockAmount - badCont;
console.log(`[adv] lockAmount=${lockAmount} honestFloor=${floor} badContinuation=${badCont} attemptedTake=${stolen} (steal=${STEAL})`);

const covInput = {
  transactionId: lOutpoint.transactionId, index: lOutpoint.index, value: lockAmount,
  scriptPublicKey: spk, signatureScript: k.payToScriptHashSignatureScript(redeem, "41" + "00".repeat(65)),
  redeem, role: "pool",
};
const outputs = [
  { value: badCont, scriptPublicKey: spk, role: "lock-cont", binding: { covid: st.lock.covid, authorizingInput: 0 } },
  { value: stolen, scriptPublicKey: k.payToAddressScript(w.address), role: "recipient" },
];
const funding = (await client.getUtxosByAddresses([w.address])).entries[0];
const spend = { kind: "claim", inputs: [covInput], outputs, economics: {} };
let asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: 10_000n });
const fee = sdk.spend.estimateNativeFee(k, NETWORK, asm, 100);
asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: fee });
const tx = asm.transaction;
tx.lockTime = lockTimeMs;
const ins = tx.inputs; ins[0].sequence = 0n; tx.inputs = ins;
const sig = k.createInputSignature(tx, 0, w.priv, k.SighashType.All);
const ins2 = tx.inputs; ins2[0].signatureScript = k.payToScriptHashSignatureScript(redeem, sig); tx.inputs = ins2;
asm.fundingInputIndexes.forEach((i) => { const a = tx.inputs; a[i].signatureScript = k.createInputSignature(tx, i, w.priv, k.SighashType.All); tx.inputs = a; });

try {
  const { transactionId } = await client.submitTransaction({ transaction: tx });
  console.log(`[adv] !!! CRITICAL: over-claim ACCEPTED: ${transactionId} — SCRIPT FAILED TO ENFORCE FLOOR`);
} catch (e) {
  console.log(`[adv] ✅ rejected as expected: ${String(e.message || e).split("\n")[0]}`);
}
client.disconnect();
