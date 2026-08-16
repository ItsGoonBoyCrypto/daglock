//! LOCK_V1 offline audit harness — runs the Dagger Locks covenant through the REAL rusty-kaspa
//! script interpreter (TxScriptEngine) over many synthetic transactions. No node, no fees, no
//! median-time waits. Exhaustively exercises the script-level spend conditions:
//!   sig gate, cliff (CLTV), vesting math, continuation floor, recursion (own-spk), lineage.
//!
//! The header-context finalization (tx.lock_time < past-median-time) is NOT a script-engine
//! concern and is validated separately on live TN10 (see dagger/locks-covenant).
//!
//! Run: cargo run --release --example lock_harness -p kaspa-txscript
//! Exit code 0 = every case behaved as expected; nonzero = an unexpected accept/reject (a finding).

use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{
        CovenantBinding, MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
        VerifiableTransaction,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine,
    caches::Cache,
    covenants::CovenantsContext,
    opcodes::codes::*,
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};
use secp256k1::{Keypair, Secp256k1};

const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

#[derive(Clone)]
struct LockParams {
    beneficiary_xonly: [u8; 32],
    start_ms: i64,
    cliff_ms: i64,
    period_ms: i64,
    n_periods: i64,
    per_period: i64,
}

impl LockParams {
    fn total(&self) -> i64 {
        self.n_periods * self.per_period
    }
}

/// Build LOCK_V1 redeem script — must match dagger/locks-covenant/src/lockv1.js byte-for-byte.
fn build_lock_redeem(p: &LockParams) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.add_data(&p.beneficiary_xonly).unwrap();
    sb.add_op(OpCheckSigVerify).unwrap();
    sb.add_i64(p.cliff_ms).unwrap();
    sb.add_op(OpCheckLockTimeVerify).unwrap();
    sb.add_op(OpTxLockTime).unwrap();
    sb.add_i64(p.start_ms).unwrap();
    sb.add_op(OpSub).unwrap();
    sb.add_i64(p.period_ms).unwrap();
    sb.add_op(OpDiv).unwrap();
    sb.add_i64(p.n_periods).unwrap();
    sb.add_op(OpMin).unwrap();
    sb.add_i64(p.per_period).unwrap();
    sb.add_op(OpMul).unwrap();
    sb.add_i64(p.total()).unwrap();
    sb.add_op(OpSwap).unwrap();
    sb.add_op(OpSub).unwrap(); // floor = TOTAL - vested
    sb.add_op(OpDup).unwrap();
    sb.add_i64(0).unwrap();
    sb.add_op(OpGreaterThan).unwrap();
    sb.add_op(OpIf).unwrap();
    sb.add_op(OpTxInputIndex).unwrap();
    sb.add_op(OpTxOutputAmount).unwrap();
    sb.add_op(OpLessThanOrEqual).unwrap();
    sb.add_op(OpVerify).unwrap();
    sb.add_op(OpTxInputIndex).unwrap();
    sb.add_op(OpTxOutputSpk).unwrap();
    sb.add_op(OpTxInputIndex).unwrap();
    sb.add_op(OpTxInputSpk).unwrap();
    sb.add_op(OpEqualVerify).unwrap();
    sb.add_op(OpTxInputIndex).unwrap();
    sb.add_op(OpOutputCovenantId).unwrap();
    sb.add_op(OpTxInputIndex).unwrap();
    sb.add_op(OpInputCovenantId).unwrap();
    sb.add_op(OpEqualVerify).unwrap();
    sb.add_op(OpElse).unwrap();
    sb.add_op(OpDrop).unwrap();
    sb.add_op(OpEndIf).unwrap();
    sb.add_op(OpTrue).unwrap();
    sb.drain()
}

/// Off-chain mirror of the script's vesting math (must equal what the script computes).
fn vested_at(p: &LockParams, now_ms: i64) -> i64 {
    if now_ms < p.cliff_ms {
        return 0;
    }
    let elapsed = now_ms - p.start_ms;
    if elapsed < 0 {
        return 0;
    }
    let k = (elapsed / p.period_ms).min(p.n_periods);
    k * p.per_period
}
fn floor_at(p: &LockParams, now_ms: i64) -> i64 {
    (p.total() - vested_at(p, now_ms)).max(0)
}

/// A synthetic claim we can perturb for positive/negative testing.
struct Claim {
    lock_amount: i64,
    lock_time: i64,
    cont_amount: i64,       // output[0] value (the re-locked remainder)
    cont_spk_matches: bool, // output[0].spk == own spk ?
    cont_covid_matches: bool,
    include_cont: bool, // false = terminate (final-claim shape)
    sign: bool,
    signer_is_beneficiary: bool,
}

/// Execute one claim through the real engine. Returns Ok(()) on accept, Err on reject.
fn run_claim(p: &LockParams, c: &Claim, beneficiary: &Keypair, other: &Keypair) -> Result<(), String> {
    let redeem = build_lock_redeem(p);
    let spk = pay_to_script_hash_script(&redeem);
    let cov_id = Hash::from_u64_word(0xDA66E12);
    let other_covid = Hash::from_u64_word(0x9999);

    // Input: the lock UTXO, carrying covenant id `cov_id`.
    let utxo = UtxoEntry::new(c.lock_amount as u64, spk.clone(), 0, false, Some(cov_id));
    let input = TransactionInput::new(TransactionOutpoint::new(Hash::from_u64_word(1), 0), vec![], 0, 1);

    // Outputs: [0]=continuation (optional), [1]=beneficiary payout.
    let mut outputs = Vec::new();
    if c.include_cont {
        let cont_spk = if c.cont_spk_matches { spk.clone() } else { pay_to_script_hash_script(&[0x51]) };
        let cont_covid = if c.cont_covid_matches { cov_id } else { other_covid };
        outputs.push(TransactionOutput {
            value: c.cont_amount as u64,
            script_public_key: cont_spk,
            covenant: Some(CovenantBinding::new(0, cont_covid)),
        });
    }
    let payout = (c.lock_amount - if c.include_cont { c.cont_amount } else { 0 }).max(0);
    outputs.push(TransactionOutput::new(payout as u64, pay_to_script_hash_script(&[0x51])));

    let tx = Transaction::new(1, vec![input], outputs, c.lock_time as u64, Default::default(), 0, vec![]);

    // Sign over the sighash, then assemble the P2SH signature_script: <sig> <redeem>.
    let mut mtx = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let reused = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&mtx.as_verifiable(), 0, SIG_HASH_ALL, &reused);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let mut sb = ScriptBuilder::new();
    if c.sign {
        let kp = if c.signer_is_beneficiary { beneficiary } else { other };
        let sig = kp.sign_schnorr(msg);
        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(sig.as_ref().as_slice());
        signature.push(SIG_HASH_ALL.to_u8());
        sb.add_data(&signature).unwrap();
    } else {
        sb.add_data(&[0u8; 65]).unwrap(); // malformed placeholder
    }
    sb.add_data(&redeem).unwrap();
    mtx.tx.inputs[0].signature_script = sb.drain();

    // Build covenants context (validates bindings) then execute the script engine.
    let ptx = mtx.tx.clone();
    let populated = kaspa_consensus_core::tx::PopulatedTransaction::new(&ptx, vec![utxo.clone()]);
    let sig_cache = Cache::new(10_000);
    let reused2 = SigHashReusedValuesUnsync::new();
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| format!("covctx: {e:?}"))?;
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused2).with_covenants_ctx(&cov_ctx);
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &populated.tx.inputs[0],
        0,
        &populated.entries[0],
        ctx,
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute().map_err(|e| format!("{e:?}"))
}

// Deterministic LCG for reproducible fuzzing.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo { return lo; }
        lo + (self.next() % ((hi - lo + 1) as u64)) as i64
    }
}

/// Randomized differential fuzz: over many random schedules and claim times, an HONEST claim must be
/// ACCEPTED and a single-fault claim must be REJECTED by the real interpreter. Returns failure count.
fn fuzz(beneficiary: &Keypair, other: &Keypair, bx: [u8; 32], iters: u32) -> u32 {
    let mut rng = Rng(0xDA6C_1EEE_2026);
    let mut fails = 0u32;
    let threshold = LOCK_TIME_THRESHOLD as i64;
    for _ in 0..iters {
        let n_periods = rng.range(1, 200);
        let period_ms = rng.range(60_000, 10_000_000);
        // keep perPeriod well under the 2^62/n cap and realistic
        let per_period = rng.range(1, (4_611_686_018_427_387_903i64 / n_periods).min(2_000_000_000_000));
        let start = threshold + rng.range(1_000_000, 10_000_000_000);
        let span = n_periods * period_ms;
        let cliff = start + rng.range(0, span);
        let p = LockParams { beneficiary_xonly: bx, start_ms: start, cliff_ms: cliff, period_ms, n_periods, per_period };
        let total = p.total();
        let end = start + span;

        // --- honest claim at a random valid time ---
        let t = rng.range(cliff, end + span / (n_periods.max(1))); // may exceed end (caps at N)
        let fl = floor_at(&p, t);
        let honest = Claim {
            lock_amount: total, lock_time: t,
            cont_amount: fl, cont_spk_matches: true, cont_covid_matches: true,
            include_cont: fl > 0, sign: true, signer_is_beneficiary: true,
        };
        if run_claim(&p, &honest, beneficiary, other).is_err() {
            fails += 1;
            println!("[fuzz FAIL] honest claim rejected: n={n_periods} per={per_period} period={period_ms} t={t} floor={fl}");
        }

        // --- single-fault claim: must be rejected ---
        let fault = rng.range(0, 5);
        let mut bad = Claim {
            lock_amount: total, lock_time: t.max(cliff),
            cont_amount: fl, cont_spk_matches: true, cont_covid_matches: true,
            include_cont: true, sign: true, signer_is_beneficiary: true,
        };
        let mut applicable = true;
        match fault {
            0 => { if fl > 1 { bad.cont_amount = fl - rng.range(1, fl); } else { applicable = false; } } // underfund
            1 => bad.cont_spk_matches = false,
            2 => bad.cont_covid_matches = false,
            3 => bad.sign = false,
            4 => bad.signer_is_beneficiary = false,
            _ => { // lock_time before cliff
                if cliff > start { bad.lock_time = rng.range(start, cliff - 1); bad.cont_amount = floor_at(&p, bad.lock_time); }
                else { applicable = false; }
            }
        }
        // Continuation-branch faults (underfund / wrong-spk / wrong-covid) only bite when floor>0.
        // At floor==0 the script is a final claim and imposes NO continuation constraint (correct),
        // so those faults are legitimately accepted. Sig faults (3,4) and CLTV (5) apply regardless.
        if (fault == 0 || fault == 1 || fault == 2) && fl == 0 { applicable = false; }
        if applicable && run_claim(&p, &bad, beneficiary, other).is_ok() {
            fails += 1;
            println!("[fuzz FAIL] fault {fault} ACCEPTED: n={n_periods} per={per_period} t={t} floor={fl} cont={}", bad.cont_amount);
        }
    }
    fails
}

/// Run the script engine for ONE input of a multi-input tx (mirrors how consensus checks each input).
fn run_input(tx: &Transaction, utxos: Vec<UtxoEntry>, idx: usize) -> Result<(), String> {
    let populated = kaspa_consensus_core::tx::PopulatedTransaction::new(tx, utxos);
    let sig_cache = Cache::new(10_000);
    let reused = SigHashReusedValuesUnsync::new();
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| format!("covctx: {e:?}"))?;
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused).with_covenants_ctx(&cov_ctx);
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated, &populated.tx.inputs[idx], idx, &populated.entries[idx], ctx,
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute().map_err(|e| format!("{e:?}"))
}

/// Multi-lock: spend TWO distinct locks (A@input0, B@input1) in one tx. Verifies each input binds to
/// its OWN output index (OpTxInputIndex), so continuations can't cross-satisfy. Returns fail count.
fn multi_lock_test(beneficiary: &Keypair, bx: [u8; 32]) -> u32 {
    let mut fails = 0u32;
    let start = LOCK_TIME_THRESHOLD as i64 + 1_000_000;
    // Two DIFFERENT schedules => different redeem bytes => different spk, and distinct covids.
    let pa = LockParams { beneficiary_xonly: bx, start_ms: start, cliff_ms: start + 60_000, period_ms: 60_000, n_periods: 10, per_period: 50_000_000 };
    let pb = LockParams { beneficiary_xonly: bx, start_ms: start, cliff_ms: start + 60_000, period_ms: 60_000, n_periods: 10, per_period: 70_000_000 };
    let (ra, rb) = (build_lock_redeem(&pa), build_lock_redeem(&pb));
    let (spk_a, spk_b) = (pay_to_script_hash_script(&ra), pay_to_script_hash_script(&rb));
    let (cov_a, cov_b) = (Hash::from_u64_word(0xAAAA), Hash::from_u64_word(0xBBBB));
    let t = start + 5 * 60_000; // both mid-vest, floors > 0
    let (fa, fb) = (floor_at(&pa, t), floor_at(&pb, t));
    let (ta, tb) = (pa.total(), pb.total());

    // Build a 2-input tx with a configurable output layout, then sign both inputs and run each.
    let build = |outs: Vec<TransactionOutput>| -> (Transaction, Vec<UtxoEntry>) {
        let inputs = vec![
            TransactionInput::new(TransactionOutpoint::new(Hash::from_u64_word(1), 0), vec![], 0, 1),
            TransactionInput::new(TransactionOutpoint::new(Hash::from_u64_word(2), 0), vec![], 0, 1),
        ];
        let utxos = vec![
            UtxoEntry::new(ta as u64, spk_a.clone(), 0, false, Some(cov_a)),
            UtxoEntry::new(tb as u64, spk_b.clone(), 0, false, Some(cov_b)),
        ];
        let tx = Transaction::new(1, inputs, outs, t as u64, Default::default(), 0, vec![]);
        let mut mtx = MutableTransaction::with_entries(tx, utxos.clone());
        let reused = SigHashReusedValuesUnsync::new();
        for (idx, redeem) in [(0usize, &ra), (1usize, &rb)] {
            let sh = calc_schnorr_signature_hash(&mtx.as_verifiable(), idx, SIG_HASH_ALL, &reused);
            let msg = secp256k1::Message::from_digest_slice(sh.as_bytes().as_slice()).unwrap();
            let sig = beneficiary.sign_schnorr(msg);
            let mut sigv = Vec::with_capacity(65);
            sigv.extend_from_slice(sig.as_ref().as_slice());
            sigv.push(SIG_HASH_ALL.to_u8());
            let mut sb = ScriptBuilder::new();
            sb.add_data(&sigv).unwrap();
            sb.add_data(redeem).unwrap();
            mtx.tx.inputs[idx].signature_script = sb.drain();
        }
        (mtx.tx, utxos)
    };
    let cont = |val: i64, spk: &kaspa_consensus_core::tx::ScriptPublicKey, cov: Hash| TransactionOutput {
        value: val as u64, script_public_key: spk.clone(), covenant: Some(CovenantBinding::new(0, cov)),
    };
    let payout = TransactionOutput::new(1, pay_to_script_hash_script(&[0x51]));

    // 1) HONEST: out[0]=A-cont, out[1]=B-cont (authorizing_input must match the index they sit under).
    {
        let mut outs = vec![cont(fa, &spk_a, cov_a), cont(fb, &spk_b, cov_b), payout.clone()];
        outs[1].covenant = Some(CovenantBinding::new(1, cov_b)); // B-cont authorized by input 1
        let (tx, u) = build(outs);
        let r0 = run_input(&tx, u.clone(), 0);
        let r1 = run_input(&tx, u, 1);
        if r0.is_err() || r1.is_err() { fails += 1; println!("[multi FAIL] honest 2-lock rejected: A={:?} B={:?}", r0.err(), r1.err()); }
        else { println!("[PASS] multi-lock honest: both inputs accept (each binds its own output index)"); }
    }
    // 2) SWAPPED continuations: put B-cont at index 0, A-cont at index 1. Input 0 checks out[0] (now
    //    B's spk/covid) => must REJECT.
    {
        let mut a_at1 = cont(fa, &spk_a, cov_a); a_at1.covenant = Some(CovenantBinding::new(1, cov_a));
        let outs = vec![cont(fb, &spk_b, cov_b), a_at1, payout.clone()];
        let (tx, u) = build(outs);
        let r0 = run_input(&tx, u, 0);
        if r0.is_ok() { fails += 1; println!("[multi FAIL] swapped continuations ACCEPTED for input 0"); }
        else { println!("[PASS] multi-lock swapped continuations: input 0 rejects ({:?})", r0.err().unwrap_or_default().chars().take(28).collect::<String>()); }
    }
    // 3) SHARED single continuation: only out[0]=A-cont, out[1]=payout (no B-cont). Input 1 checks
    //    out[1] (payout) => wrong spk => must REJECT (one output can't satisfy both locks).
    {
        let outs = vec![cont(fa, &spk_a, cov_a), payout.clone()];
        let (tx, u) = build(outs);
        let r1 = run_input(&tx, u, 1);
        if r1.is_ok() { fails += 1; println!("[multi FAIL] shared-output ACCEPTED for input 1"); }
        else { println!("[PASS] multi-lock shared-output: input 1 rejects (no cross-satisfaction)"); }
    }
    fails
}

fn main() {
    let secp = Secp256k1::new();
    let mut seed1 = [7u8; 32];
    seed1[0] = 1;
    let beneficiary = Keypair::from_seckey_slice(&secp, &seed1).unwrap();
    let mut seed2 = [7u8; 32];
    seed2[0] = 2;
    let other = Keypair::from_seckey_slice(&secp, &seed2).unwrap();
    let bx = beneficiary.x_only_public_key().0.serialize();

    // Base schedule: start at threshold, 10 periods x 60_000ms, cliff at start+120_000, 0.5 KAS/period.
    let start = LOCK_TIME_THRESHOLD as i64 + 1_000_000;
    let base = LockParams {
        beneficiary_xonly: bx,
        start_ms: start,
        cliff_ms: start + 120_000,
        period_ms: 60_000,
        n_periods: 10,
        per_period: 50_000_000,
    };
    let total = base.total();

    // Cross-check: the Rust builder length (must match JS builder output for these params).
    let redeem = build_lock_redeem(&base);
    println!("[harness] LOCK_V1 redeem = {} bytes", redeem.len());

    let mut fails = 0u32;
    let mut n = 0u32;
    // helper closure: assert a claim's accept/reject matches expectation.
    let mut check = |name: &str, c: Claim, expect_ok: bool| {
        n += 1;
        let got = run_claim(&base, &c, &beneficiary, &other);
        let ok = got.is_ok();
        let verdict = if ok == expect_ok { "PASS" } else { "**FAIL**" };
        if ok != expect_ok {
            fails += 1;
        }
        println!(
            "[{verdict}] {name}: expected={}, got={} {}",
            if expect_ok { "ACCEPT" } else { "REJECT" },
            if ok { "ACCEPT" } else { "REJECT" },
            got.err().map(|e| format!("({e})")).unwrap_or_default()
        );
    };

    // honest claim at time T with continuation exactly at floor.
    let honest = |now: i64, cont: i64, incl: bool| Claim {
        lock_amount: total,
        lock_time: now,
        cont_amount: cont,
        cont_spk_matches: true,
        cont_covid_matches: true,
        include_cont: incl,
        sign: true,
        signer_is_beneficiary: true,
    };

    // ---- Boundary: cliff timing ----
    check("pre-cliff (cliff-1ms)", honest(base.cliff_ms - 1, floor_at(&base, base.cliff_ms - 1), true), false);
    check("at cliff", honest(base.cliff_ms, floor_at(&base, base.cliff_ms), true), true);
    check("mid-vest (k=5)", honest(start + 5 * 60_000, floor_at(&base, start + 5 * 60_000), true), true);
    // fully vested -> terminate (no continuation)
    let end = start + base.n_periods * base.period_ms;
    check("full vest, terminate", honest(end, 0, false), true);
    check("past end caps at N, terminate", honest(end + 10 * 60_000, 0, false), true);

    // ---- Floor enforcement ----
    let t = start + 4 * 60_000; // vested=4 periods=2 KAS, floor=3 KAS
    let f = floor_at(&base, t);
    check("continuation == floor", honest(t, f, true), true);
    check("continuation > floor (overpay ok)", honest(t, f + 25_000_000, true), true);
    check("continuation < floor (STEAL)", honest(t, f - 25_000_000, true), false);
    check("continuation = 0 while floor>0 (drain)", honest(t, 0, true), false);

    // ---- Recursion / lineage ----
    let mut c = honest(t, f, true);
    c.cont_spk_matches = false;
    check("continuation wrong spk", c, false);
    let mut c = honest(t, f, true);
    c.cont_covid_matches = false;
    check("continuation wrong covid", c, false);

    // ---- Signature gate ----
    let mut c = honest(t, f, true);
    c.sign = false;
    check("no/garbage signature", c, false);
    let mut c = honest(t, f, true);
    c.signer_is_beneficiary = false;
    check("third-party signature", c, false);

    // ---- CLTV bypass attempts ----
    // lock_time below cliff must fail even though everything else is honest.
    check("lock_time < cliff (CLTV)", honest(base.cliff_ms - 60_000, floor_at(&base, base.cliff_ms - 60_000), true), false);

    // ---- Property sweep: for many times, honest claim at exact floor must ACCEPT; underpay by 1 must REJECT.
    let mut prop_fail = 0u32;
    let mut t2 = base.cliff_ms;
    while t2 <= end {
        let f = floor_at(&base, t2);
        // exact floor
        if run_claim(&base, &honest(t2, f, f > 0), &beneficiary, &other).is_err() {
            prop_fail += 1;
        }
        // underpay by 1 sompi (only meaningful when floor>0)
        if f > 0 {
            let bad = honest(t2, f - 1, true);
            if run_claim(&base, &bad, &beneficiary, &other).is_ok() {
                prop_fail += 1;
                println!("[**FAIL**] property: underpay-by-1 accepted at t={t2}");
            }
        }
        t2 += 7_000; // step 7s to hit many sub-period offsets
    }
    n += 1;
    if prop_fail > 0 {
        fails += 1;
        println!("[**FAIL**] property sweep: {prop_fail} anomalies");
    } else {
        println!("[PASS] property sweep: exact-floor accept & underpay-by-1 reject across vest window");
    }

    // ---- randomized differential fuzz (real interpreter) ----
    let fuzz_iters = 20_000u32;
    let fuzz_fails = fuzz(&beneficiary, &other, bx, fuzz_iters);
    n += 1;
    if fuzz_fails > 0 { fails += 1; println!("[**FAIL**] fuzz: {fuzz_fails} anomalies over {fuzz_iters} iters"); }
    else { println!("[PASS] differential fuzz: {fuzz_iters} random schedules — honest accepted, single-fault rejected"); }

    // ---- multi-lock / multi-input (red-team cross-satisfaction concern) ----
    let ml_fails = multi_lock_test(&beneficiary, bx);
    n += 3;
    if ml_fails > 0 { fails += 1; }

    println!("\n[harness] {} checks, {} failures", n, fails);
    if fails > 0 {
        std::process::exit(1);
    }
}
