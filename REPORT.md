# worm-lab — build report

**Version:** 1.0.0 · **Repo:** https://github.com/happymode-25/worm-lab (private) ·
**Built:** Oct 2026 · **Basis:** the ODE coursework in `types-ode-ODE.docx` +
the egress-broker discipline (single file, stdlib only, fail-closed, tamper
evident, mutation-swept, CI-gated).

## 1. What was built

`worm-lab.py` is a one-file, zero-dependency (Python 3.9+ stdlib) simulator of
worm / malware propagation through a population of `N` hosts, using the
compartment epidemic models SIR and SEIR. It integrates its own Runge–Kutta 4
stepper — no numpy, no scipy — and verifies that stepper against closed forms
instead of trusting a library. Every run is appended to a hash-chained JSONL
audit store and can be proven untampered later.

## 2. Security-engineering stance

The point of the tool is not "plot a nice curve"; it is that a security
planner should be able to trust the numbers and the record of them:

- **Fail-closed input.** `i0 > N`, `β ≤ 0`, `γ ≤ 0`, unknown commands:
  refused with an exit code and a reason. Nothing is silently clamped.
- **Fail-closed planning.** `sweep` reports the *worst* peak and worst final
  removal across an uncertainty box; the e2e suite asserts that envelope is
  at least as pessimistic as every single corner run. When you do not know
  `β`, you plan for the bound, not the guess.
- **Fail-closed evidence.** If the audit chain does not verify *immediately
  after a write*, the tool refuses to report the run — better no record than
  a record that cannot be evidenced.

## 3. The math, and how it is proved

```
SIR:   dS/dt = −βSI/N   dI/dt = βSI/N − γI   dR/dt = γI
SEIR:  dS/dt = −βSI/N   dE/dt = βSI/N − σE   dI/dt = σE − γI   dR/dt = γI
R0 = β/γ   (well-mixed, all-S initial)
```

Selftest checks the properties that matter, not the code path:

| Property | How it is checked |
|---|---|
| RK4 is fourth-order | halving the step shrinks the error ~16× (ratio asserted in [8, 40]) |
| The integrator is correct | fine-step RK4 matches `e^(2t)` at t=1 to 1e-9 |
| Numerical vs analytical | early-stage SIR matches `I0·e^((β−γ)t)` to 1e-3, and the linear window is *load-bearing*: on a run that goes nonlinear, excluding late points changes the verdict by an order of magnitude |
| Host conservation | `S+I+R == N` and `S+E+I+R == N` at every step (≤1e-6) |
| Epidemic threshold | R₀ ≤ 1 ⇒ infection never grows; R₀ > 1 ⇒ it peaks then burns out and removes hosts |
| Determinism | identical arguments ⇒ byte-identical trajectories |
| Worst-case sweep | the envelope bounds every grid run |

## 4. Audit trail

`{seq, ts, tool, version, model, params, metrics, prev, hash}` with
`hash = sha256(canonical(record minus hash/prev) + "|" + prev)`; record 0 is
anchored to a genesis sentinel. `verify` checks seq contiguity, prev linkage,
and content hash *independently* — all problems are reported, not just the
first. Editing a number, deleting the oldest record, and inserting a forged
record are all caught and named.

Honest limitation: trimming the tail of the file cannot be detected from
inside the file. External anchoring (log shipper, SIEM, append-only media) is
the documented answer if that matters.

## 5. Defects found and fixed during bring-up

| Defect | Symptom | Fix |
|---|---|---|
| `compare` re-registered `--step` | argparse died at startup | `set_defaults` instead of a second `add_argument` |
| `metrics()` read the wrong column for SEIR | `StopIteration` crash on `seir` | peak computed over the infected index (2), not exposed (1) |
| `verify_store` skipped later checks after a seq mismatch | deleted oldest record only reported a shift, name dropped | all three checks run independently; every problem reported |
| compare defaults drifted out of the linear window | `compare` was out of tolerance at N=10,000 / 30 days | short window (10 d), large population (100 k) by default |
| compare-window mutation survived the sweep | exclusion of late points was not load-bearing | new check: on a nonlinear run the window must change the verdict by ≥10× |

## 6. Verification — what the green is, and that it can fail

| Gate | Result |
|---|---|
| `ci/import_gate.py` | 0 non-stdlib imports across the repo |
| `selftest` | 21/21 checks |
| `tests/test_worm_lab.py` | 23/23 tests, real subprocess runs of the CLI |
| `ci/prove_suites_can_fail.py` | RK4 mutation and injected-check mutation both turn the suites red; restore is green again |
| `ci/mutation.py` | 10 real mutants killed, semantically-identical canary survives, live file hash unchanged (scratch-copy only) |
| CI matrix | Python 3.9 / 3.11 / 3.13 × linux / macos / windows, count floors: 21 selftest checks, 23 e2e tests |

The suite is not trusted on a green run alone: `prove_suites_can_fail` breaks
the code on purpose and requires the failures to be *named checks*, not
crashes, and the mutation sweep requires the canary to survive — otherwise
every verdict in the run is void.

## 7. Reproduce

```powershell
git clone https://github.com/happymode-25/worm-lab   # private; needs access
cd worm-lab
python ci/import_gate.py
python worm-lab.py selftest
python tests/test_worm_lab.py
python ci/prove_suites_can_fail.py
python ci/mutation.py
```

## 8. Relationship to the previous build

The egress-broker patterns carried over deliberately: a separate pure selftest
plus a subprocess e2e suite, count floors in CI, an import gate, a
prove-suites-can-fail harness, a canary-anchored mutation sweep on a scratch
copy with the live file hashed before and after, and a README that states
guarantees *and* their limits. egress-broker proves that egress decisions and
audit rows are trustworthy; worm-lab proves the same for propagation numbers
and their scenario record.