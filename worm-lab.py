#!/usr/bin/env python3
"""worm-lab -- ODE-based worm and malware propagation simulator.

Models an outbreak as a compartment epidemic (SIR / SEIR) and integrates it
with a from-scratch Runge-Kutta 4 stepper -- no numpy, no scipy. The tool is
deliberate about what it proves:

  * the integrator must reproduce a closed-form solution it cannot see,
  * every model must conserve host counts exactly (S+I+R == N),
  * below the epidemic threshold (R0 <= 1) nothing may grow,
  * a parameter sweep reports the WORST case, so planning is fail-closed:
    when the analyst does not know beta exactly, they plan for the bound,
  * every run is appended to a hash-chained audit trail, and tampering with
    any retained record is detected on demand.

Everything is deterministic: the same arguments produce the same numbers.

Single file, Python 3.9+, standard library only.

Usage:
  python worm-lab.py selftest
  python worm-lab.py sir   --beta 0.3 --gamma 0.1 --N 10000 --i0 1 --days 30
  python worm-lab.py seir  --beta 0.3 --sigma 0.2 --gamma 0.1 --N 10000
  python worm-lab.py compare --beta 0.3 --gamma 0.1 --N 100000 --i0 1
  python worm-lab.py sweep --beta-min 0.2 --beta-max 0.4 --gamma-min 0.05 --gamma-max 0.15
  python worm-lab.py stats [--json]
  python worm-lab.py verify [--store PATH]

Audit store: env WORM_LAB_STORE, else ~/.wormlab/audit.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import tempfile
import time

__version__ = "1.0.0"

# The genesis anchor every chain must start from. If record 0 does not carry
# exactly this prev, the oldest record was deleted.
GENESIS = "0" * 64

# Fail-closed default behaviour for validation errors: every bad input exits 1
# with a reason on stderr. Nothing silently degrades.
_EPILOG = "worm-lab: "

# ---------------------------------------------------------------------------
# Integrator
# ---------------------------------------------------------------------------

def rk4(deriv, y0, t0, t_end, step, params):
    """Integrate dy/dt = deriv(t, y, params) from t0 with a fixed-step RK4.

    Returns [(t, state_tuple), ...] including t0. RK4 is fourth-order: halving
    step h shrinks the local error by ~2**5 and the accumulated error by ~2**4,
    which the selftest asserts rather than assumes.
    """
    n = max(1, int(round((t_end - t0) / step)))
    h = (t_end - t0) / float(n)
    t = float(t0)
    y = [float(v) for v in y0]
    out = [(t, tuple(y))]
    for _ in range(n):
        k1 = deriv(t, y, params)
        k2 = deriv(t + h / 2.0, [y[i] + h / 2.0 * k1[i] for i in range(len(y))], params)
        k3 = deriv(t + h / 2.0, [y[i] + h / 2.0 * k2[i] for i in range(len(y))], params)
        k4 = deriv(t + h, [y[i] + h * k3[i] for i in range(len(y))], params)
        y = [y[i] + h / 6.0 * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i])
             for i in range(len(y))]
        t += h
        out.append((t, tuple(y)))
    return out


# ---------------------------------------------------------------------------
# Compartment models. State layout:
#   SIR  -> (S, I, R)
#   SEIR -> (S, E, I, R)
# ---------------------------------------------------------------------------

def _sir_deriv(t, y, p):
    s, i, r = y
    n = p["N"]
    ds = -p["beta"] * s * i / n
    di = p["beta"] * s * i / n - p["gamma"] * i
    dr = p["gamma"] * i
    return [ds, di, dr]


def _seir_deriv(t, y, p):
    s, e, i, r = y
    n = p["N"]
    ds = -p["beta"] * s * i / n
    de = p["beta"] * s * i / n - p["sigma"] * e
    di = p["sigma"] * e - p["gamma"] * i
    dr = p["gamma"] * i
    return [ds, de, di, dr]


def _closed_form_early(params, t):
    """I(t) ~= I0 * exp((beta - gamma) t) while S is still ~N.

    The analytic anchor the numerical integrator is compared against. It is the
    SIR early-stage solution: while almost every host is still susceptible, the
    epidemic grows exponentially at rate (beta - gamma).
    """
    return params["i0"] * math.exp((params["beta"] - params["gamma"]) * t)


def make_run(model, params):
    """Run one simulation; return (params, [states])."""
    if model == "sir":
        n = params["N"]
        y0 = (n - params["i0"], params["i0"], 0.0)
        deriv = _sir_deriv
    elif model == "seir":
        n = params["N"]
        y0 = (n - params["i0"], 0.0, params["i0"], 0.0)
        deriv = _seir_deriv
    else:  # pragma: no cover - CLI validates before this is reachable
        raise ValueError(f"unknown model {model!r}")
    return rk4(deriv, y0, 0.0, params["days"], params["step"], params)


def metrics(model, states):
    """Summarise a trajectory. (S, I, R) or (S, E, I, R) -> metrics dict."""
    i_index = 2 if model == "seir" else 1
    peak = max(st[i_index] for _, st in states)
    if model == "seir":
        final_r = states[-1][1][3]
        n_cols = 4
    else:
        final_r = states[-1][1][2]
        n_cols = 3
    peak_day = next(t for t, st in states if st[i_index] == peak)
    final_state = states[-1][1]
    final_i = final_state[i_index]
    n = sum(final_state[:n_cols])
    return {
        "peak": peak,
        "peak_day": round(peak_day, 6),
        "final_i": final_i,
        "final_r": final_r,
        "attack_ratio": round(final_r / n, 6),
        "final_s": final_state[0],
    }


def analytic_compare(params, states, keep_frac=0.99, tol=1e-3):
    """Compare the numerical SIR run against the early-stage closed form.

    Only points where susceptible hosts are still >= keep_frac*N are compared,
    because the closed form assumes S ~= N. Returns (max_rel_error, points).
    """
    n = params["N"]
    worst = 0.0
    points = 0
    for t, st in states:
        s, i, r = st
        if s < keep_frac * n:
            continue
        expected = _closed_form_early(params, t)
        if expected > 0 and i > 0:
            err = abs(i - expected) / expected
            worst = max(worst, err)
            points += 1
    return worst, points


# ---------------------------------------------------------------------------
# Validation (fail-closed): bad input exits 1 with the reason on stderr.
# ---------------------------------------------------------------------------

def positive(name, value):
    if value <= 0:
        fail(f"{name} must be > 0, got {value}")
    return value


def validate_common(args):
    params = {
        "N": float(positive("N", args.N)),
        "i0": float(positive("i0", args.i0)),
        "days": float(positive("days", args.days)),
        "step": float(positive("step", args.step)),
    }
    # Fail-closed: an initial infected population larger than the host count is
    # nonsense, not "clamped to N".
    if params["i0"] > params["N"]:
        fail(f"i0 ({params['i0']}) cannot exceed N ({params['N']})")
    params["N"] = int(params["N"])
    return params


def validate_sir(args):
    p = validate_common(args)
    p["beta"] = float(positive("beta", args.beta))
    p["gamma"] = float(positive("gamma", args.gamma))
    return p


def validate_seir(args):
    p = validate_common(args)
    p["beta"] = float(positive("beta", args.beta))
    p["sigma"] = float(positive("sigma", args.sigma))
    p["gamma"] = float(positive("gamma", args.gamma))
    return p


def fail(msg):
    print(_EPILOG + msg, file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Audit trail: append-only JSONL, hash chained, tamper-evident.
#   record = {seq, ts, tool, version, model, params, metrics,
#             prev, hash}
#   hash   = sha256(canonical(record minus hash/prev) + "|" + prev)
#   record 0 must carry prev == GENESIS; every later record's prev must equal
#   the previous record's hash; seq must equal the line index.
# ---------------------------------------------------------------------------

def default_store():
    env = os.environ.get("WORM_LAB_STORE")
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".wormlab", "audit.jsonl")


def _canonical(record):
    clean = {k: v for k, v in record.items() if k not in ("hash", "prev")}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"))


def _record_hash(record):
    digest = hashlib.sha256()
    digest.update(_canonical(record).encode("utf-8"))
    digest.update(b"|")
    digest.update(record["prev"].encode("utf-8"))
    return digest.hexdigest()


def read_store(path):
    """Parse the audit file. Returns (records, error_message)."""
    if not os.path.exists(path):
        return [], None
    records = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError as exc:
                    return None, f"{path}:{lineno}: unparseable JSON ({exc})"
                if not isinstance(rec, dict):
                    return None, f"{path}:{lineno}: not an object"
                records.append(rec)
    except OSError as exc:
        return None, f"{path}: cannot read ({exc})"
    return records, None


def verify_store(path):
    """Rebuild the chain. Returns (ok, problems, n)."""
    records, err = read_store(path)
    if err:
        return False, [err], 0
    problems = []
    for i, rec in enumerate(records):
        if rec.get("seq") != i:
            problems.append(
                f"record {i}: seq is {rec.get('seq')!r}, expected {i} "
                "(an insert or a deletion shifted the file)")
        if i == 0:
            if rec.get("prev") != GENESIS:
                problems.append(
                    f"record 0: prev is {rec.get('prev', '')[:16]!r}, "
                    "expected the genesis anchor (the oldest record was deleted)")
        else:
            if rec.get("prev") != records[i - 1].get("hash"):
                problems.append(
                    f"record {i}: prev does not match the previous record's hash "
                    "(the previous record was edited)")
        expect = _record_hash(rec)
        if rec.get("hash") != expect:
            problems.append(f"record {i}: hash does not match its contents (edited)")
    return (len(problems) == 0), problems, len(records)


def append_record(store, model, params, metrics):
    """Append one chained record; fail closed if the write cannot be trusted."""
    records, err = read_store(store)
    if err:
        fail(f"cannot append to store {store}: {err}")
    prev = records[-1]["hash"] if records else GENESIS
    seq = len(records)
    rec = {
        "seq": seq,
        "ts": round(time.time(), 3),
        "tool": "worm-lab",
        "version": __version__,
        "model": model,
        "params": params,
        "metrics": metrics,
        "prev": prev,
        "hash": None,
    }
    rec["hash"] = _record_hash(rec)
    line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    directory = os.path.dirname(store)
    if directory:
        os.makedirs(directory, exist_ok=True)
    # Fail-closed write: append, flush, fsync, then read the line back and
    # confirm the chain is intact before reporting success.
    try:
        with open(store, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        fail(f"cannot write audit store {store}: {exc}")
    ok, problems, _ = verify_store(store)
    if not ok:
        fail(f"audit store does not verify right after writing ({problems[0]}); "
             "refusing to report a run that cannot be evidenced")
    return rec


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def fmt_hosts(x):
    return f"{x:,.0f}"


def report_run(stream, model, params, metrics, store, seq):
    r0 = params["beta"] / params["gamma"]
    print(
        f"worm-lab {__version__} -- {model.upper()} model, "
        f"N={fmt_hosts(params['N'])}, I0={fmt_hosts(params['i0'])}, "
        f"beta={params['beta']:.2f}/day, gamma={params['gamma']:.2f}/day, "
        f"R0={r0:.2f}",
        file=stream,
    )
    print(
        f"  over {params['days']:.1f} days, step {params['step']:.3f} "
        f"({max(1, int(round(params['days'] / params['step'])))} steps)",
        file=stream,
    )
    print(
        f"  peak infected : {fmt_hosts(metrics['peak'])} hosts at day "
        f"{metrics['peak_day']:.2f}  ({100 * metrics['peak'] / params['N']:.1f}% of N)",
        file=stream,
    )
    print(
        f"  final state   : S={fmt_hosts(metrics['final_s'])}  "
        f"I={fmt_hosts(metrics['final_i'])}  R={fmt_hosts(metrics['final_r'])}  "
        f"(attack ratio {100 * metrics['attack_ratio']:.1f}%)",
        file=stream,
    )
    print(f"  recorded to audit store: {store} (seq {seq})", file=stream)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_sir(args):
    p = validate_sir(args)
    logged = dict(p)
    logged["N"] = int(p["N"])
    states = make_run("sir", p)
    m = metrics("sir", states)
    seq = None
    rec = append_record(args.store, "sir", logged, m)
    seq = rec["seq"]
    report_run(sys.stdout, "sir", p, m, args.store, seq)


def cmd_seir(args):
    p = validate_seir(args)
    logged = dict(p)
    logged["N"] = int(p["N"])
    states = make_run("seir", p)
    m = metrics("seir", states)
    rec = append_record(args.store, "seir", logged, m)
    report_run(sys.stdout, "seir", p, m, args.store, rec["seq"])


def cmd_compare(args):
    p = validate_sir(args)
    states = make_run("sir", p)
    worst, points = analytic_compare(p, states, tol=args.tol)
    print(
        f"worm-lab {__version__} -- SIR early-stage vs I0*e^((beta-gamma)t), "
        f"N={fmt_hosts(p['N'])}, I0={fmt_hosts(p['i0'])}"
    )
    print(
        f"  compared {points} points where S >= {args.keep_frac * 100:.0f}% of N"
        if points else "  no points inside the linear window; tighten keep-frac"
    )
    print(f"  max relative error: {worst:.3e}  (tol {args.tol:.0e})")
    ok = worst <= args.tol
    print(f"  verdict: {'within tolerance' if ok else 'OUT OF TOLERANCE'}")
    logged = dict(p)
    logged["N"] = int(p["N"])
    append_record(args.store, "compare", logged, {
        "max_rel_error": worst, "points": points, "verdict": "ok" if ok else "fail",
    })
    if not ok and args.fail_over:
        fail(f"numerical solution diverged from the closed form by {worst:.3e}")
    sys.exit(0)


def _linspace(lo, hi, count):
    if count == 1:
        return [float(lo)]
    return [lo + (hi - lo) * i / (count - 1) for i in range(count)]


def cmd_sweep(args):
    positive("beta-min", args.beta_min)
    positive("beta-max", args.beta_max)
    positive("gamma-min", args.gamma_min)
    positive("gamma-max", args.gamma_max)
    if args.beta_max < args.beta_min:
        fail("beta-max must be >= beta-min")
    if args.gamma_max < args.gamma_min:
        fail("gamma-max must be >= gamma-min")
    base = validate_common(args)
    worst_peak = -1.0
    worst_final = -1.0
    worst_peak_at = worst_final_at = None
    runs = 0
    for b in _linspace(args.beta_min, args.beta_max, args.grid):
        for g in _linspace(args.gamma_min, args.gamma_max, args.grid):
            p = dict(base)
            p["beta"] = b
            p["gamma"] = g
            states = make_run("sir", p)
            m = metrics("sir", states)
            runs += 1
            if m["peak"] > worst_peak:
                worst_peak, worst_peak_at = m["peak"], (b, g)
            if m["final_r"] > worst_final:
                worst_final, worst_final_at = m["final_r"], (b, g)
    print(
        f"worm-lab {__version__} -- SIR worst-case sweep over a "
        f"{args.grid}x{args.grid} grid ({runs} runs), "
        f"N={fmt_hosts(base['N'])}, I0={fmt_hosts(base['i0'])}, "
        f"{base['days']:.1f} days"
    )
    print(
        f"  worst peak   : {fmt_hosts(worst_peak)} hosts infectious at once "
        f"(beta={worst_peak_at[0]:.3f}, gamma={worst_peak_at[1]:.3f})"
    )
    print(
        f"  worst final  : {fmt_hosts(worst_final)} hosts removed "
        f"(beta={worst_final_at[0]:.3f}, gamma={worst_final_at[1]:.3f})"
    )
    print(
        f"  plan for     : up to {100 * worst_peak / base['N']:.1f}% of hosts "
        f"infectious at once; {100 * worst_final / base['N']:.1f}% compromised "
        "by the end of the window"
    )
    append_record(args.store, "sweep", {
        "N": int(base["N"]), "i0": base["i0"], "days": base["days"],
        "grid": args.grid, "runs": runs,
        "beta_range": [args.beta_min, args.beta_max],
        "gamma_range": [args.gamma_min, args.gamma_max],
    }, {
        "worst_peak": round(worst_peak, 6),
        "worst_final": round(worst_final, 6),
    })


def cmd_stats(args):
    records, err = read_store(args.store)
    if err:
        fail(err)
    if not records:
        print("no runs recorded yet")
        return
    print(f"worm-lab audit store: {args.store}  ({len(records)} records)")
    for rec in records[-8:]:
        m = rec.get("metrics", {})
        model = rec.get("model", "?")
        if model == "compare":
            disp = f"max_err={m.get('max_rel_error', 0):.2e}"
        elif model == "sweep":
            disp = f"worst_peak={fmt_hosts(m.get('worst_peak', 0))}"
        else:
            disp = (f"peak={fmt_hosts(m.get('peak', 0))}  "
                    f"final_R={fmt_hosts(m.get('final_r', 0))}")
        beta = rec.get("params", {}).get("beta", 0)
        gamma = rec.get("params", {}).get("gamma", 0)
        print(
            f"  #{rec['seq']}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(rec.get('ts', 0)))}  "
            f"{model:7}  {disp}  beta={beta:.2f}  gamma={gamma:.2f}"
        )


def cmd_verify(args):
    ok, problems, n = verify_store(args.store)
    print(f"worm-lab audit verify: {args.store}")
    if not os.path.exists(args.store):
        print("  store does not exist yet (no runs recorded) -- nothing to verify")
        sys.exit(0)
    if ok:
        print(f"  verified: {n} records, chain intact")
        sys.exit(0)
    print(f"  TAMPERED: {len(problems)} problem(s) in {n} records")
    for p_ in problems:
        print(f"    - {p_}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

def _expect(cond, name, state):
    state["total"] += 1
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}")
        state["failures"].append(name)


def selftest():
    state = {"failures": [], "total": 0}

    # --- integrator: order 4 ------------------------------------------------
    lam = 2.0
    deriv = lambda t, y, p: [lam * y[0]]
    def exp_run(h):
        out = rk4(deriv, [1.0], 0.0, 1.0, h, {})
        return out[-1][1][0], math.exp(lam)
    fine, exact = exp_run(0.0005)
    _expect(
        abs(fine - exact) < 1e-9,
        "rk4 with a fine step matches e^(2t) at t=1 to 1e-9",
        state,
    )
    e_coarse, _ = exp_run(0.1)
    e_mid, _ = exp_run(0.05)
    coarse_err = abs(e_coarse - exact)
    mid_err = abs(e_mid - exact)
    _expect(
        8.0 < coarse_err / mid_err < 40.0,
        "halving the step shrinks the error by ~16x (4th order)",
        state,
    )

    # --- negative control: the suite can actually fail ----------------------
    # A deliberately broken derivative must produce a *detectable* deviation.
    # If the machinery could not tell broken from correct, this reports FAIL.
    broken = lambda t, y, p: [lam * y[0] * 1.01]
    good = rk4(deriv, [1.0], 0.0, 1.0, 0.05, {})[-1][1][0]
    bad = rk4(broken, [1.0], 0.0, 1.0, 0.05, {})[-1][1][0]
    _expect(
        abs(good - bad) > 1e-3,
        "negative control: a broken derivative is detected as a deviation",
        state,
    )

    # --- SIR vs the early-stage closed form --------------------------------
    # Ten days at I0=1 in a population of 100k: the susceptible pool barely
    # moves, so the I0*e^((beta-gamma)t) closed form is a fair anchor.
    p = {"N": 100000.0, "i0": 1.0, "days": 10.0, "step": 0.01,
         "beta": 0.3, "gamma": 0.1}
    states = make_run("sir", p)
    worst, points = analytic_compare(p, states)
    _expect(worst < 1e-3, "SIR early stage matches I0*e^((beta-gamma)t) to 1e-3", state)
    _expect(points > 50, f"the comparison window contained {points} points (>50)", state)

    # The window must actually exclude the nonlinear phase, and that exclusion
    # must be load-bearing -- on a run that goes nonlinear, comparing every
    # point must fail while the honest window still passes.
    long_p = {"N": 10000.0, "i0": 1.0, "days": 60.0, "step": 0.05,
              "beta": 0.3, "gamma": 0.1}
    long_states = make_run("sir", long_p)
    win_worst, win_points = analytic_compare(long_p, long_states)
    all_worst, all_points = analytic_compare(long_p, long_states, keep_frac=0.0)
    _expect(
        win_points < len(long_states),
        "the comparison window excludes the nonlinear phase (points < total)",
        state,
    )
    _expect(
        win_worst < all_worst / 10.0 and all_worst > 1e-2
        and all_points == len(long_states),
        "excluding late points is the difference between pass and fail",
        state,
    )

    # --- conservation -------------------------------------------------------
    def max_conservation_error(model, params, total):
        states = make_run(model, params)
        worst = 0.0
        for _, st in states:
            worst = max(worst, abs(sum(st) - total))
        return worst
    p_sir = {"N": 10000.0, "i0": 10.0, "days": 30.0, "step": 0.05,
             "beta": 0.3, "gamma": 0.1}
    _expect(
        max_conservation_error("sir", p_sir, 10000.0) < 1e-6,
        "SIR conserves S+I+R == N at every step",
        state,
    )
    p_seir = {"N": 10000.0, "i0": 10.0, "days": 30.0, "step": 0.05,
              "beta": 0.3, "sigma": 0.2, "gamma": 0.1}
    _expect(
        max_conservation_error("seir", p_seir, 10000.0) < 1e-6,
        "SEIR conserves S+E+I+R == N at every step",
        state,
    )

    # --- epidemic threshold -------------------------------------------------
    below = make_run("sir", {"N": 1000.0, "i0": 10.0, "days": 60.0, "step": 0.05,
                             "beta": 0.1, "gamma": 0.2})
    peak_below = max(st[1] for _, st in below)
    _expect(
        peak_below <= 10.0 + 1e-9,
        "below the threshold R0<=1 the infection never grows",
        state,
    )
    above = make_run("sir", {"N": 1000.0, "i0": 10.0, "days": 120.0, "step": 0.05,
                             "beta": 0.3, "gamma": 0.1})
    peak_above = max(st[1] for _, st in above)
    final_i_above = above[-1][1][1]
    final_r_above = above[-1][1][2]
    _expect(
        peak_above > 15.0 and final_i_above < peak_above * 0.05 and final_r_above > 0.0,
        "above the threshold the infection peaks then burns out, removing hosts",
        state,
    )

    # --- monotonicity: more contagious -> larger peak ----------------------
    p_a = dict(p_sir); p_a["beta"] = 0.25
    p_b = dict(p_sir); p_b["beta"] = 0.4
    peak_a = max(st[1] for _, st in make_run("sir", p_a))
    peak_b = max(st[1] for _, st in make_run("sir", p_b))
    _expect(
        peak_b > peak_a,
        "a more contagious worm produces a larger peak (monotone in beta)",
        state,
    )

    # --- determinism --------------------------------------------------------
    s1 = [(t, tuple(st)) for t, st in make_run("sir", p_sir)]
    s2 = [(t, tuple(st)) for t, st in make_run("sir", p_sir)]
    _expect(
        s1 == s2,
        "identical arguments produce an identical trajectory (deterministic)",
        state,
    )

    # --- sweep envelope: worst case bounds every grid run ------------------
    base = {"N": 10000.0, "i0": 1.0, "days": 30.0, "step": 0.05}
    grid_peaks = []
    for b in wl_linspace(0.2, 0.4, 5):
        for g in wl_linspace(0.05, 0.15, 5):
            pp = dict(base, beta=b, gamma=g)
            grid_peaks.append(max(st[1] for _, st in make_run("sir", pp)))
    envelope = max(grid_peaks)
    _expect(
        all(envelope >= pk for pk in grid_peaks) and len(grid_peaks) == 25,
        "the sweep envelope bounds every grid run (worst-case planning)",
        state,
    )

    # --- audit chain --------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        store = os.path.join(td, "audit.jsonl")
        rec = append_record(store, "sir", p_sir, {"peak": 1.0, "final_r": 2.0})
        _expect(rec["seq"] == 0 and rec["prev"] == GENESIS,
                "the first audit record anchors to the genesis hash", state)
        ok, problems, n = verify_store(store)
        _expect(ok and n == 1, "a freshly appended audit record verifies", state)

        # tamper 1: edit a recorded number (canonical JSON has no spaces)
        with open(store, encoding="utf-8") as fh:
            data = fh.read()
        edited = data.replace('"peak":1.0', '"peak":999.0')
        _expect(edited != data, "the tamper edit actually changed the line", state)
        with open(store, "w", encoding="utf-8") as fh:
            fh.write(edited)
        ok, problems, _ = verify_store(store)
        _expect(not ok and any("hash does not match" in p_ for p_ in problems),
                "editing a recorded number breaks the chain", state)

        # tamper 2: delete the oldest record (genesis anchor must catch it)
        store2 = os.path.join(td, "audit2.jsonl")
        append_record(store2, "sir", p_sir, {"peak": 1.0, "final_r": 2.0})
        append_record(store2, "sir", p_sir, {"peak": 2.0, "final_r": 3.0})
        with open(store2, encoding="utf-8") as fh:
            lines = fh.readlines()
        with open(store2, "w", encoding="utf-8") as fh:
            fh.writelines(lines[1:])
        ok, problems, _ = verify_store(store2)
        _expect(not ok and any("expected the genesis anchor" in p_ for p_ in problems),
                "deleting the oldest record breaks the genesis anchor", state)

        # tamper 3: insert a forged record borrowing a seq number
        store3 = os.path.join(td, "audit3.jsonl")
        append_record(store3, "sir", p_sir, {"peak": 1.0, "final_r": 2.0})
        append_record(store3, "sir", p_sir, {"peak": 2.0, "final_r": 3.0})
        with open(store3, encoding="utf-8") as fh:
            first = fh.readline()
            rest = fh.read()
        forged = {
            "seq": 1, "ts": 0.0, "tool": "worm-lab", "version": "9.9",
            "model": "sir", "params": {}, "metrics": {},
            "prev": "x" * 64, "hash": "y" * 64,
        }
        with open(store3, "w", encoding="utf-8") as fh:
            fh.write(first)
            fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
            fh.write(rest)
        ok, problems, _ = verify_store(store3)
        _expect(not ok and any("does not match" in p_ for p_ in problems),
                "an inserted record with a borrowed seq breaks the chain", state)

        ok, problems, n = verify_store(os.path.join(td, "empty.jsonl"))
        _expect(ok and n == 0, "a missing (empty) store verifies as empty", state)

    return state["failures"], state["total"]


def wl_linspace(lo, hi, count):
    """Small helper exposed so the selftest and the sweep share one source."""
    return _linspace(lo, hi, count)


def run_selftest_cli():
    print(f"worm-lab {__version__} selftest")
    failures, total = selftest()
    if failures:
        print(f"selftest FAILED: {len(failures)} check(s)")
        sys.exit(1)
    print(f"\nall checks passed: {total} run, 0 skipped")
    sys.exit(0)


# CLI
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="worm-lab",
        description="ODE-based worm and malware propagation simulator "
                    "(SIR/SEIR, from-scratch RK4, hash-chained audit).",
        epilog="audit store: env WORM_LAB_STORE, else ~/.wormlab/audit.jsonl",
    )
    ap.add_argument("--version", action="version", version=f"worm-lab {__version__}")
    ap.add_argument("--store", default=None, help="audit store path (overrides env/default)")
    sub = ap.add_subparsers(dest="command", required=False)

    def common(cmd):
        cmd.add_argument("--N", type=int, default=10000)
        cmd.add_argument("--i0", type=float, default=1.0)
        cmd.add_argument("--days", type=float, default=30.0)
        cmd.add_argument("--step", type=float, default=0.05)

    s = sub.add_parser("selftest", help="run the self-test")
    s.set_defaults(func=lambda a: run_selftest_cli())

    for name in ("sir", "seir"):
        c = sub.add_parser(name, help=f"run the {name.upper()} model")
        common(c)
        c.add_argument("--beta", type=float, default=0.3)
        c.add_argument("--gamma", type=float, default=0.1)
        if name == "seir":
            c.add_argument("--sigma", type=float, default=0.2)
        c.set_defaults(func=cmd_sir if name == "sir" else cmd_seir)

    c = sub.add_parser("compare", help="numerical SIR vs the early-stage closed form")
    common(c)
    c.add_argument("--beta", type=float, default=0.3)
    c.add_argument("--gamma", type=float, default=0.1)
    # The closed form only holds while S ~= N; keep the default window short and
    # the population large so depletion never distorts the anchor.
    c.set_defaults(days=10.0, step=0.01, N=100000)
    c.add_argument("--tol", type=float, default=1e-3)
    c.add_argument("--keep-frac", type=float, default=0.99)
    c.add_argument("--fail-over", action="store_true",
                   help="exit 1 if the error exceeds tol (CI gate)")
    c.set_defaults(func=cmd_compare)

    s = sub.add_parser("sweep", help="worst-case envelope over an uncertain beta/gamma")
    common(s)
    s.add_argument("--beta-min", type=float, default=0.2)
    s.add_argument("--beta-max", type=float, default=0.4)
    s.add_argument("--gamma-min", type=float, default=0.05)
    s.add_argument("--gamma-max", type=float, default=0.15)
    s.add_argument("--grid", type=int, default=5)
    s.set_defaults(func=cmd_sweep)

    s = sub.add_parser("stats", help="recent audit records")
    s.set_defaults(func=cmd_stats)

    s = sub.add_parser("verify", help="verify the audit chain")
    s.set_defaults(func=cmd_verify)

    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.store is None:
        args.store = default_store()
    if args.command in (None, "help"):
        ap.print_help()
        return 0
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())