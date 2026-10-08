"""Prove the selftest and the e2e suite can actually fail, rather than
asserting that they can.

A green suite is not evidence of anything on its own: it is equally consistent
with "the code is correct" and with "the checks are not connected to the code".
The only way to tell those apart is to break the code on purpose and require
the suites to notice.

Three mutations, each checking something different:

  1. A behaviour change in the integrator. `rk4`'s k3 estimate is perturbed so
     the scheme stops being fourth-order. If the selftest and the e2e suite are
     genuinely wired to the math, checks about the integrator stop passing.
  2. A check failure with no code change. If a failing check does not produce a
     non-zero exit, mutation 1 would have "passed" for the wrong reason.
  3. A restore check, because a harness that leaves the tree broken proves
     nothing about the next run.

Mutations must fail *as checks*, not as crashes. A SyntaxError also exits
non-zero, so a bare exit-code assertion would be satisfied by a file too broken
to run. The output is required to name a failing check.

Usage:  python ci/prove_suites_can_fail.py
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

TOOL = pathlib.Path("worm-lab.py")

# Behaviour mutation: k3 is estimated at the wrong midpoint, so RK4 loses its
# fourth-order global accuracy. The selftest's "4th order" and "matches e^2t"
# checks and the e2e suite's compare gate all depend on the true scheme, so a
# green result would mean none of them exercise this function.
BEHAVIOUR_OLD = (
    "        k3 = deriv(t + h / 2.0, [y[i] + h / 2.0 * k2[i] for i in range(len(y))], params)\n"
)
BEHAVIOUR_NEW = (
    "        k3 = deriv(t + h / 2.0, [y[i] + h * 1.0 * k2[i] for i in range(len(y))], params)  # deliberately broken by CI\n"
)

# Reporting mutation: no engine code changes, one check is made unsatisfiable.
# Guards the exit path itself, so mutation 1 cannot pass by exiting non-zero
# for some unrelated reason.
REPORT_OLD = '    return state["failures"], state["total"]\n'
REPORT_NEW = (
    '    _expect(False, "negative control injected by CI", state)\n'
    "\n"
    '    return state["failures"], state["total"]\n'
)


def read_source() -> str:
    """Read the tool without translating line endings.

    `open(..., newline=None)` is the default and it rewrites CRLF to LF on the
    way in and LF to CRLF on the way out; a read/write pair through it is not
    an identity on Windows and the restore would leave a phantom diff behind.
    """
    with open(TOOL, encoding="utf-8", newline="") as fh:
        return fh.read()


def write_source(text: str) -> None:
    with open(TOOL, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_selftest() -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOL), "selftest"],
        capture_output=True, text=True, timeout=600,
    )
    return proc.returncode, proc.stdout + proc.stderr


def run_e2e() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        capture_output=True, text=True, timeout=600,
    )
    # A suite that fails to even collect is not a failing suite, it is a crash.
    if proc.returncode and "FAILED" not in proc.stdout + proc.stderr:
        return 1
    return proc.returncode


def named_check_failure(output: str) -> str | None:
    """The first check the selftest reported as failing, or None."""
    for line in output.splitlines():
        if line.startswith("  FAIL "):
            return line[len("  FAIL "):].strip()
    return None


def attempt(label: str, old: str, new: str, expect_check: bool) -> bool:
    """Apply one mutation in place, require both suites to fail, then restore.

    The original bytes are held in memory and restored in a finally, and only
    the mutated text is ever written to disk.
    """
    original = read_source()
    count = original.count(old)
    if count != 1:
        print(f"  FAIL  {label}: anchor matched {count} times, expected exactly 1")
        return False

    ok = True
    try:
        write_source(original.replace(old, new))
        code, output = run_selftest()
    finally:
        write_source(original)

    if code == 0:
        print(f"  FAIL  {label}: selftest still exited 0 with the code broken")
        ok = False
    else:
        named = named_check_failure(output)
        if named is None:
            print(f"  FAIL  {label}: exited {code} but named no failing check.")
            print("        A crash is not a failing test.")
            for line in [l for l in output.splitlines() if l.strip()][-6:]:
                print(f"        {line}")
            ok = False
        else:
            verb = "failed the check" if expect_check else "exited non-zero"
            print(f"  ok    {label}: {verb} -> {code}")
            print(f"          {named}")

    # The e2e suite must fall over too. Run it against the still-mutated tool.
    if code != 0:
        try:
            write_source(original.replace(old, new))
            e2e_code = run_e2e()
            if e2e_code == 0:
                print(f"  FAIL  {label}: e2e suite passed with the code broken")
                ok = False
            else:
                print(f"  ok    {label}: e2e suite also failed -> {e2e_code}")
        finally:
            write_source(original)

    # Restoring must be green again. If it is not, the harness has left the
    # tree in a state where every later run inherits the damage.
    code, output = run_selftest()
    if code != 0:
        print(f"  FAIL  {label}: the restored tool does not pass (exit {code})")
        ok = False
    else:
        checks = sum(1 for l in output.splitlines() if l.startswith("  ok   "))
        print(f"  ok    {label}: restored, {checks} checks green")
    return ok


def main() -> int:
    if not TOOL.is_file():
        print(f"run this from the repo root; {TOOL} not found")
        return 1

    print("baseline")
    code, output = run_selftest()
    checks = sum(1 for l in output.splitlines() if l.startswith("  ok   "))
    if code != 0:
        print(f"  FAIL  the suite does not pass before anything is broken (exit {code})")
        for line in output.splitlines()[-15:]:
            print(f"        {line}")
        return 1
    print(f"  ok    green before we touch anything: {checks} checks")

    results = [
        attempt("behaviour mutation (rk4 k3)", BEHAVIOUR_OLD, BEHAVIOUR_NEW, expect_check=True),
        attempt("reporting mutation", REPORT_OLD, REPORT_NEW, expect_check=True),
    ]
    if all(results):
        print("\nthe suites fail when the code is broken and when a check fails, "
              "and pass when it is not")
        return 0
    print("\nthis suite cannot be trusted to fail, so it cannot be trusted to pass")
    return 1


if __name__ == "__main__":
    sys.exit(main())