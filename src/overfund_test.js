/**
 * F1 on-chain proof — TN10. A malicious creator funds a lock with MORE than TOTAL. The excess is
 * immediately liquid (unvested), so the badge MUST refuse it. This creates such a lock for real and
 * shows evaluateBadge (fed the real on-chain genesis value) returns NO badge.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadKaspa } from "@kronsdk/kron-sdk/wasm";
import * as sdk from "@kronsdk/kron-sdk";
import { buildLockRedeem, lockSpk, lockAddress, hexToBytes, bytesToHex } from "./lockv1.js";
import { evaluateBadge } from "./verify.js";

const NETWORK = "testnet-10";
const st = JSON.parse(readFileSync(fileURLToPath(new URL("../state.json", import.meta.url)), "utf8"));
const k = await loadKaspa();
const priv = new k.PrivateKey(st.priv);
const pub = priv.toPublicKey();
const address = pub.toAddress(NETWORK).toString();

function signFunding(tx, idxs) {
  const sigs = idxs.map((i) => k.createInputSignature(tx, i, priv, k.SighashType.All));
  const ins = tx.inputs; idxs.forEach((i, j) => { ins[i].signatureScript = sigs[j]; }); tx.inputs = ins;
}

const now = BigInt(Date.now());
const params = { beneficiaryPub: hexToBytes(pub.toXOnlyPublicKey().toString()), startMs: now, cliffMs: now + 120_000n, periodMs: 60_000n, nPeriods: 10n, perPeriod: 50_000_000n };
const total = params.nPeriods * params.perPeriod;         // 5 KAS
const EXTRA = 300_000_000n;                                // +3 KAS of unvested excess
const funded = total + EXTRA;                              // 8 KAS genesis value
const redeem = buildLockRedeem(k, params);
const spk = lockSpk(k, redeem);

const client = new k.RpcClient({ resolver: new k.Resolver(), networkId: NETWORK });
await client.connect();
const es = (await client.getUtxosByAddresses([address])).entries.sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
const funding = es[0];
const go = { transactionId: funding.outpoint.transactionId, index: funding.outpoint.index };
const covid = sdk.genesis.genesisCovenantId(k, go, [{ index: 0, value: funded, scriptPublicKey: spk }]);

// Deliberately fund with `funded` (> TOTAL) — this is the malicious/mistaken creation.
const spend = { kind: "init", inputs: [], outputs: [{ value: funded, scriptPublicKey: spk, role: "lock", binding: { covid, authorizingInput: 0 } }], economics: {} };
let asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: address, networkFee: 20_000n });
const fee = sdk.spend.estimateNativeFee(k, NETWORK, asm, 100);
asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: address, networkFee: fee });
signFunding(asm.transaction, asm.fundingInputIndexes);
const { transactionId } = await client.submitTransaction({ transaction: asm.transaction });
const lockAddr = lockAddress(k, redeem, NETWORK);
console.log(`[overfund] created lock funded=${Number(funded) / 1e8} KAS but TOTAL=${Number(total) / 1e8} KAS  tx=${transactionId}`);

// Read the real on-chain genesis value and evaluate the badge.
await new Promise((r) => setTimeout(r, 8000));
const lockUtxos = (await client.getUtxosByAddresses([lockAddr])).entries;
const genesisValue = BigInt(lockUtxos[0].amount);
console.log(`[overfund] on-chain genesis value = ${Number(genesisValue) / 1e8} KAS`);

const verdict = evaluateBadge({ redeem, genesisValueSompi: genesisValue, currentAmountSompi: genesisValue, tokenSupplyBase: 100_000_000_000n });
console.log(`[overfund] badge verdict: ${verdict.badge}  (${verdict.reason})`);
const pass = verdict.badge === "NONE" && verdict.funded === false;
console.log(pass ? "\n✅ F1 PROVEN ON-CHAIN: over-funded lock is REFUSED a badge" : "\n❌ F1 FAILURE: over-funded lock was badged");
client.disconnect();
process.exit(pass ? 0 : 1);
