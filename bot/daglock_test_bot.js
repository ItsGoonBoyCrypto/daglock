/**
 * DagLock TEST bot — Telegram, MAINNET, REAL KAS. Owner-gated. For validating DagLock before any
 * public wiring. Dependency-free Telegram (native fetch long-poll). Reuses the AUDITED builder
 * (lockv1.js) + verifier (verify.js) unchanged; tx assembly mirrors the TN10-proven lifecycle.
 *
 * Safety: owner-only (first /start binds the owner, or pin OWNER_ID in .env); every broadcast is a
 * two-step confirm (/new→/confirm, /claim→/claimgo); hard DAGLOCK_MAX_KAS cap; genesis value == TOTAL
 * (F1); claims SIGHASH_ALL (F2). Burner wallet key lives in bot/bot_state.json (gitignored).
 *
 * Run:  cd locks-covenant && node bot/daglock_test_bot.js
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { loadKaspa } from "@kronsdk/kron-sdk/wasm";
import * as sdk from "@kronsdk/kron-sdk";
import { buildLockRedeem, lockSpk, lockAddress, continuationFloor, vestedAt, hexToBytes, bytesToHex } from "../src/lockv1.js";
import { evaluateBadge, describeLock } from "../src/verify.js";

// ---- env ----
const ENV = fileURLToPath(new URL("./.env", import.meta.url));
for (const line of (existsSync(ENV) ? readFileSync(ENV, "utf8").split("\n") : [])) {
  const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
  if (m && !line.trim().startsWith("#")) process.env[m[1]] ??= m[2];
}
const TOKEN = process.env.BOT_TOKEN;
if (!TOKEN) { console.error("BOT_TOKEN missing in bot/.env"); process.exit(1); }
const API = `https://api.telegram.org/bot${TOKEN}`;
const NETWORK = "mainnet";
const MAX_KAS = BigInt(Math.floor(Number(process.env.DAGLOCK_MAX_KAS ?? "25")));
const SOMPI = 100_000_000n;

// ---- state (burner wallet + current lock) ----
const STATE = fileURLToPath(new URL("./bot_state.json", import.meta.url));
const st = existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : {};
if (process.env.OWNER_ID) st.owner ??= Number(process.env.OWNER_ID);
const save = () => writeFileSync(STATE, JSON.stringify(st, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
const kas = (s) => (Number(s) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });

// ---- kaspa ----
const k = await loadKaspa();
let client;
async function rpc() {
  if (client && client.isConnected) return client;
  try { if (client) await client.disconnect(); } catch {}
  client = new k.RpcClient({ resolver: new k.Resolver(), networkId: NETWORK });
  await client.connect();
  return client;
}
// Resilient RPC call: reconnects + retries on a dropped WebSocket (public nodes drop idle sockets).
async function withClient(fn) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try { return await fn(await rpc()); }
    catch (e) {
      const msg = String(e?.message || e);
      if (attempt === 2 || !/WebSocket|not connected|disconnect|closed|timeout/i.test(msg)) throw e;
      client = null; await new Promise((r) => setTimeout(r, 700));
    }
  }
}
function wallet() {
  if (!st.priv) return null;
  const priv = new k.PrivateKey(st.priv);
  const pub = priv.toPublicKey();
  return { priv, pub, xonly: hexToBytes(pub.toXOnlyPublicKey().toString()), address: pub.toAddress(NETWORK).toString() };
}
const utxos = async (a) => (await withClient((c) => c.getUtxosByAddresses([a]))).entries;
function signFunding(tx, idxs, sk) {
  const sigs = idxs.map((i) => k.createInputSignature(tx, i, sk, k.SighashType.All));
  const ins = tx.inputs; idxs.forEach((i, j) => { ins[i].signatureScript = sigs[j]; }); tx.inputs = ins;
}

// ---- Telegram ----
async function tg(method, body) {
  const r = await fetch(`${API}/${method}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return r.json();
}
const send = (chat, text) => tg("sendMessage", { chat_id: chat, text, parse_mode: "HTML", disable_web_page_preview: true });

let pending = null; // { kind:'create'|'claim', ... } two-step confirm state

async function doCreate(args) {
  const w = wallet();
  const [totalKasArg, cliffMinArg, perMinArg, nArg] = args;
  if (!totalKasArg || !cliffMinArg || !perMinArg || !nArg) throw new Error("usage: /new &lt;totalKAS&gt; &lt;cliffMins&gt; &lt;periodMins&gt; &lt;nPeriods&gt;");
  const now = BigInt(Date.now());
  const perPeriod = BigInt(Math.round((Number(totalKasArg) / Number(nArg)) * 1e8));
  const params = { beneficiaryPub: w.xonly, startMs: now, cliffMs: now + BigInt(Math.round(Number(cliffMinArg) * 60000)), periodMs: BigInt(Math.round(Number(perMinArg) * 60000)), nPeriods: BigInt(nArg), perPeriod };
  const total = params.nPeriods * params.perPeriod;
  if (total !== BigInt(Math.round(Number(totalKasArg) * 1e8))) throw new Error(`total ${kas(total)} != ${totalKasArg} KAS — pick nPeriods that divides evenly`);
  if (total > MAX_KAS * SOMPI) throw new Error(`SAFETY: ${kas(total)} KAS exceeds cap ${MAX_KAS} KAS`);
  const redeem = buildLockRedeem(k, params);
  const d = describeLock(params);
  pending = { kind: "create", params, redeem: bytesToHex(redeem), total };
  return `<b>LOCK PREVIEW</b> (dry-run)\n` +
    `total: <b>${kas(total)} KAS</b> = ${d.nPeriods} × ${kas(perPeriod)}\n` +
    `beneficiary: <code>${w.address}</code>\n` +
    `cliff: ${d.cliff}\nend: ${d.end} (${d.durationDays}d)\n` +
    `lock addr: <code>${lockAddress(k, redeem, NETWORK)}</code>\n\n➡️ send /confirm to broadcast (irreversible), or /cancel`;
}

async function doConfirmCreate() {
  const w = wallet();
  const { params, total } = pending;
  const redeem = hexToBytes(pending.redeem);
  const spk = lockSpk(k, redeem);
  const es = (await utxos(w.address)).sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
  if (!es.length) throw new Error("no funding UTXO — fund the wallet first");
  const funding = es[0];
  const go = { transactionId: funding.outpoint.transactionId, index: funding.outpoint.index };
  const covid = sdk.genesis.genesisCovenantId(k, go, [{ index: 0, value: total, scriptPublicKey: spk }]);
  const spend = { kind: "init", inputs: [], outputs: [{ value: total, scriptPublicKey: spk, role: "lock", binding: { covid, authorizingInput: 0 } }], economics: {} };
  let asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: 20_000n });
  asm = sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: sdk.spend.estimateNativeFee(k, NETWORK, asm, 100) });
  signFunding(asm.transaction, asm.fundingInputIndexes, w.priv);
  const { transactionId } = await withClient((c) => c.submitTransaction({ transaction: asm.transaction }));
  st.lock = { covid, redeem: pending.redeem, address: lockAddress(k, redeem, NETWORK), createTx: transactionId, genesisValue: total.toString(), params: { ...params, beneficiaryPub: bytesToHex(params.beneficiaryPub) }, total: total.toString(), claims: [] };
  pending = null; save();
  return `✅ <b>BROADCAST</b>\nlock: <code>${st.lock.address}</code>\ntx: <code>${transactionId}</code>\n\n/verify then /status`;
}

function lockParams() {
  const P = st.lock.params;
  return { beneficiaryPub: hexToBytes(P.beneficiaryPub), startMs: BigInt(P.startMs), cliffMs: BigInt(P.cliffMs), periodMs: BigInt(P.periodMs), nPeriods: BigInt(P.nPeriods), perPeriod: BigInt(P.perPeriod) };
}

async function doStatus() {
  if (!st.lock) return "no lock — /new first";
  const p = lockParams();
  const es = await utxos(st.lock.address);
  const remaining = es.length ? BigInt(es[0].amount) : 0n;
  const median = BigInt((await withClient((c) => c.getBlockDagInfo())).pastMedianTime);
  const floor = continuationFloor(p, median);
  const claimable = remaining - floor > 0n ? remaining - floor : 0n;
  return `<b>STATUS</b>\nlock: <code>${st.lock.address}</code>\nremaining: <b>${kas(remaining)}</b> / ${kas(p.nPeriods * p.perPeriod)} KAS (utxos ${es.length})\nvested: ${kas(vestedAt(p, median))}  floor: ${kas(floor)}\nclaimable now: <b>${kas(claimable)} KAS</b>`;
}

async function doVerify() {
  if (!st.lock) return "no lock — /new first";
  const p = lockParams();
  const redeem = hexToBytes(st.lock.redeem);
  const es = await utxos(st.lock.address);
  const current = es.length ? BigInt(es[0].amount) : 0n;
  const b = evaluateBadge({ redeem, genesisValueSompi: BigInt(st.lock.genesisValue), currentAmountSompi: current });
  const d = describeLock(p);
  return `<b>VERIFY</b>\nverified: ${b.verified ? "✅" : "❌"}  funded: ${b.funded ? "✅" : "❌"}\nreason: ${b.reason}\nfingerprint: <code>${b.fingerprint ?? "-"}</code>\nterms: ${d.totalDisplay} KAS over ${d.nPeriods}×${d.periodSeconds}s\nends: ${d.end}\nbeneficiary pk: <code>${d.beneficiaryPubHex}</code>\non-chain locked: ${kas(current)} KAS`;
}

async function doClaimPreview() {
  if (!st.lock) return "no lock — /new first";
  const p = lockParams();
  const es = await utxos(st.lock.address);
  if (!es.length) return "no lock UTXO — already fully claimed?";
  const lu = es[0], lockAmount = BigInt(lu.amount);
  const lt = BigInt((await withClient((c) => c.getBlockDagInfo())).pastMedianTime) - 2_000n;
  if (lt < p.cliffMs) throw new Error(`cliff not matured in median-time yet (+${Number(p.cliffMs - lt) / 1000}s)`);
  const floor = continuationFloor(p, lt);
  const claimable = lockAmount - floor;
  if (claimable <= 0n) throw new Error(`nothing claimable (floor ${kas(floor)} == balance)`);
  pending = { kind: "claim", lu, lockAmount, lt, floor, claimable, finalClaim: floor === 0n };
  return `<b>CLAIM PREVIEW</b>\n${floor === 0n ? "FINAL" : "partial"} claim: <b>${kas(claimable)} KAS</b>\nre-lock floor: ${kas(floor)} KAS\n\n➡️ /claimgo to broadcast, or /cancel`;
}

async function doClaimGo() {
  const w = wallet();
  const p = lockParams();
  const redeem = hexToBytes(st.lock.redeem);
  const spk = lockSpk(k, redeem);
  const { lu, lockAmount, lt, floor, claimable, finalClaim } = pending;
  const funding = (await utxos(w.address))[0];
  if (!funding) throw new Error("no fee-funding UTXO");
  const covInput = { transactionId: lu.outpoint.transactionId, index: lu.outpoint.index, value: lockAmount, scriptPublicKey: spk, signatureScript: k.payToScriptHashSignatureScript(redeem, "41" + "00".repeat(65)), redeem, role: "pool" };
  const outputs = [];
  if (!finalClaim) outputs.push({ value: floor, scriptPublicKey: spk, role: "cont", binding: { covid: st.lock.covid, authorizingInput: 0 } });
  outputs.push({ value: claimable, scriptPublicKey: k.payToAddressScript(w.address), role: "pay" });
  const spend = { kind: finalClaim ? "claimFinal" : "claim", inputs: [covInput], outputs, economics: {} };
  const build = (fee) => sdk.spend.assembleNativeTx(k, { spend, fundingEntries: [funding], changeAddress: w.address, networkFee: fee });
  let asm = build(10_000n); asm = build(sdk.spend.estimateNativeFee(k, NETWORK, asm, 100));
  const tx = asm.transaction; tx.lockTime = lt;
  const ins = tx.inputs; ins[0].sequence = 0n; tx.inputs = ins;
  const sig = k.createInputSignature(tx, 0, w.priv, k.SighashType.All);
  const ins2 = tx.inputs; ins2[0].signatureScript = k.payToScriptHashSignatureScript(redeem, sig); tx.inputs = ins2;
  signFunding(tx, asm.fundingInputIndexes, w.priv);
  const { transactionId } = await withClient((c) => c.submitTransaction({ transaction: tx }));
  st.lock.claims.push({ tx: transactionId, claimed: claimable.toString(), final: finalClaim });
  pending = null; save();
  return `✅ ${finalClaim ? "FINAL" : "partial"} claim broadcast\ntx: <code>${transactionId}</code>\n/status`;
}

const HELP = `<b>DagLock TEST bot</b> (MAINNET, real KAS)\n\n/wallet — show/create burner address\n/balance — wallet balance\n/new &lt;KAS&gt; &lt;cliffMin&gt; &lt;perMin&gt; &lt;N&gt; — preview a lock\n/confirm — broadcast the previewed lock\n/status — vesting state\n/verify — badge + terms check\n/claim — preview a claim\n/claimgo — broadcast the claim\n/cancel — clear a pending action\n\nSmoke test: /wallet → fund → /new 2 5 5 4 → /confirm → /verify → /status → /claim → /claimgo`;

async function handle(msg) {
  const chat = msg.chat.id, from = msg.from.id, text = (msg.text || "").trim();
  // owner-gate: first /start binds the owner.
  if (!st.owner) {
    if (text.startsWith("/start")) { st.owner = from; save(); return send(chat, `👋 Owner bound: <code>${from}</code>\n${HELP}`); }
    return send(chat, "This bot is not initialized. The owner must /start first.");
  }
  if (from !== st.owner) return send(chat, "⛔ owner-only test bot.");
  const [cmd, ...args] = text.split(/\s+/);
  try {
    if (cmd === "/start" || cmd === "/help") return send(chat, HELP);
    if (cmd === "/cancel") { pending = null; return send(chat, "pending cleared."); }
    if (cmd === "/wallet") {
      if (!wallet()) { st.priv = new k.PrivateKey(randomBytes(32).toString("hex")).toString(); save(); }
      return send(chat, `burner (fund with a SMALL amount):\n<code>${wallet().address}</code>`);
    }
    if (!wallet() && cmd !== "/start") return send(chat, "no wallet — /wallet first");
    if (cmd === "/balance") { const es = await utxos(wallet().address); let s = 0n; for (const e of es) s += BigInt(e.amount); return send(chat, `balance: <b>${kas(s)} KAS</b> (utxos ${es.length})`); }
    if (cmd === "/new") return send(chat, await doCreate(args));
    if (cmd === "/confirm") { if (pending?.kind !== "create") return send(chat, "nothing to confirm — /new first"); return send(chat, await doConfirmCreate()); }
    if (cmd === "/status") return send(chat, await doStatus());
    if (cmd === "/verify") return send(chat, await doVerify());
    if (cmd === "/claim") return send(chat, await doClaimPreview());
    if (cmd === "/claimgo") { if (pending?.kind !== "claim") return send(chat, "nothing to claim — /claim first"); return send(chat, await doClaimGo()); }
    return send(chat, "unknown command — /help");
  } catch (e) {
    return send(chat, `⚠️ ${String(e.message || e).split("->").pop().trim().slice(0, 200)}`);
  }
}

// ---- long-poll loop ----
const me = await tg("getMe", {});
if (!me.ok) { console.error("bad BOT_TOKEN:", me.description); process.exit(1); }
console.log(`DagLock test bot @${me.result.username} live (mainnet). Owner: ${st.owner ?? "(first /start binds)"}`);
await rpc().then((c) => console.log(`[rpc] mainnet connected: ${c.url}`)).catch((e) => console.log("[rpc] connect deferred:", e.message));
// Keepalive: ping the node every 40s so the public WebSocket doesn't idle-drop; reconnect on failure.
setInterval(() => { withClient((c) => c.getBlockDagInfo()).catch(() => { client = null; }); }, 40_000);
let offset = 0;
for (;;) {
  try {
    const u = await tg("getUpdates", { offset, timeout: 30 });
    if (u.ok) for (const upd of u.result) { offset = upd.update_id + 1; if (upd.message?.text) await handle(upd.message); }
  } catch (e) { console.log("poll error:", e.message); await new Promise((r) => setTimeout(r, 2000)); }
}
