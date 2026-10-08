# worm-lab

An ODE-based worm and malware propagation simulator, built to the same bar as
[egress-broker](https://github.com/happymode-25/egress-broker):

- **One file, zero dependencies.** `worm-lab.py` runs on Python 3.9+ with the
  standard library alone. The integrator is a from-scratch Runge–Kutta 4 — no
  numpy, no scipy, nothing to pip-install.
- **Fail-closed by default.** Invalid input is refused with an exit code and a
  reason; planning reports are worst-case; the audit store refuses to accept a
  run it cannot evidence.
- **Tamper-evident audit trail.** Every run is appended to a hash-chained JSONL
  store. `verify` rebuilds the chain and names exactly what is wrong if
  anything was edited, deleted, or forged.
- **Provably testable.** A 21-check selftest, a 23-test end-to-end suite, a
  `prove_suites_can_fail` harness, and a 10-mutant + canary mutation sweep —
  all enforced in CI with count floors.

## What it does

Models an outbreak as a compartment epidemic — SIR and SEIR — for a population
of `N` hosts:

```
SIR:   dS/dt = -β·S·I/N      dI/dt = β·S·I/N − γ·I      dR/dt = γ·I
SEIR:  dS/dt = -β·S·I/N      dE/dt = β·S·I/N − σ·E      dI/dt = σ·E − γ·I
```

and integrates it with a fixed-step RK4 written from scratch. The discipline
is the point: nothing is believed because a library says so. The integrator is
verified against a closed form it does not see (`I₀·e^((β−γ)t)` while the
susceptible pool is still ~N), host counts must conserve exactly at every
step, and below the epidemic threshold (R₀ ≤ 1) nothing may grow.

## When to use it

- As a **planning tool** when a worm or worm-like propagation is a scenario:
  given a plausible `β`/`γ`, what fraction of hosts are infectious at once,
  and when?
- As a **fail-closed estimator** when the parameters are *not* known: `sweep`
  runs the whole uncertainty box and reports the worst case to plan for.
- As a **teaching/verification aid** for ODE coursework: numerical vs
  analytical comparison is a first-class command.
- As an **auditable record**: every run lands in the hash-chained store, so a
  scenario you explored can be proved later to be the scenario you explored.

## Quick start

```powershell
python worm-lab.py selftest                 # 21 checks, proves the math engine

python worm-lab.py sir --N 10000 --i0 1 --beta 0.3 --gamma 0.1 --days 30
python worm-lab.py seir --N 10000 --sigma 0.2 --days 45

python worm-lab.py compare                  # numerical vs I₀·e^((β−γ)t)
python worm-lab.py compare --fail-over      # CI-style gate: exit 1 out of tol

python worm-lab.py sweep --beta-min 0.2 --beta-max 0.4 `
                        --gamma-min 0.05 --gamma-max 0.15 --grid 5

python worm-lab.py stats                    # recent runs from the audit store
python worm-lab.py verify                   # prove the chain is untampered
```

The audit store lives at `~/.wormlab/audit.jsonl`, or wherever
`WORM_LAB_STORE` points, or where `--store` says.

## Commands

| Command | What it gives you |
|---|---|
| `selftest` | 21 checks: RK4 order-4 accuracy, conservation, threshold behaviour, determinism, sweep bounds, audit tamper detection |
| `sir` / `seir` | One run: peak infectious load, day of peak, final state, attack ratio, R₀ |
| `compare [--fail-over]` | Numerical vs the early-stage closed form; `--fail-over` gates on tolerance |
| `sweep` | Worst-case envelope over an uncertain β/γ box — plan for the bound, not the guess |
| `stats` | Recent runs from the audit store |
| `verify` | Rebuild the hash chain; exit 1 and name the tamper if anything is wrong |

Everything is deterministic: the same arguments produce the same numbers, and
`--version` is available everywhere.

## Fail-closed behaviour

- `i0 > N`, `β ≤ 0`, `γ ≤ 0`, unknown commands → exit 1/2 with a reason, no
  partial run, no clamped silence.
- `sweep` reports the *worst* peak and final removal across the grid, and the
  e2e suite asserts that bound covers every single corner run.
- If the audit chain does not verify *immediately after a write*, the tool
  refuses to report the run rather than record one it cannot evidence.

## Audit trail

Each record is `{seq, ts, tool, version, model, params, metrics, prev, hash}`
where `hash = sha256(canonical(record minus hash/prev) + "|" + prev)`. Record 0
must carry the genesis anchor. `verify` checks three independent things per
record — seq contiguity, prev linkage, and content hash — so it reports *all*
problems, not just the first. Editing a number, deleting the oldest record,
and inserting a forged record are all caught and named.

What it cannot do, stated honestly: trimming the *tail* of the file is not
detectable from inside the file. If that matters, anchor the last hash
externally (log shipper, SIEM, append-only media).

## Verification

| Gate | What it proves | Floor |
|---|---|---|
| `ci/import_gate.py` | zero third-party imports anywhere | — |
| `selftest` | integrator, models, audit, determinism | 21 checks |
| `tests/test_worm_lab.py` | real CLI behaviour over subprocesses | 23 tests |
| `ci/prove_suites_can_fail.py` | the suites fail when the code breaks and pass when restored | — |
| `ci/mutation.py` | 10 real mutants killed, semantically-identical canary survives | 11/11 |

Run them locally from the repo root:

```powershell
python ci/import_gate.py
python worm-lab.py selftest
python tests/test_worm_lab.py
python ci/prove_suites_can_fail.py
python ci/mutation.py
```

The mutation sweep works on a scratch copy — the live `worm-lab.py` is hashed
before and after, so a sweep can never leave a mutant behind in the repo.