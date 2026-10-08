"""worm-lab end-to-end suite.

Every test drives the real CLI as a subprocess (the tool is a single
hyphenated file, so importing is deliberately not how we test it). The store
for each test lives in a fresh temp directory, so runs are isolated.

The suite asserts outcomes the user can observe: exit codes, report fields,
fail-closed behaviour on bad input, and the hash-chained audit trail
detecting every class of tamper we know about.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "worm-lab.py"))


def run_cli(args, store=None, extra_env=None):
    env = dict(os.environ)
    if store is not None:
        env["WORM_LAB_STORE"] = store
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, TOOL] + [str(a) for a in args],
        capture_output=True, text=True, env=env,
        cwd=os.path.dirname(TOOL), timeout=120,
    )


def read_store(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


class WormLabE2E(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.store = os.path.join(self._td.name, "audit.jsonl")

    # --- core commands ------------------------------------------------------

    def test_selftest_green(self):
        r = run_cli(["selftest"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("all checks passed", r.stdout)
        self.assertNotIn("FAIL", r.stdout)

    def test_sir_default_green(self):
        r = run_cli(["sir"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SIR model", r.stdout)
        self.assertIn("R0=3.00", r.stdout)
        self.assertIn("peak infected :", r.stdout)
        # Defaults: N=10000, beta=0.3, gamma=0.1, 30 days. Early-stage
        # exponential says ~403 infected at day 30; bounds keep this honest
        # but loose across platforms.
        peak = int(re.sub(r"[^\d]", "", re.search(r"peak infected : (\d+)", r.stdout).group(1)))
        self.assertTrue(100 < peak < 1000, peak)
        self.assertIn("recorded to audit store", r.stdout)

    def test_sir_deterministic_two_runs(self):
        r1 = run_cli(["sir"], store=self.store)
        r2 = run_cli(["sir"], store=self.store)
        self.assertEqual(r1.returncode, 0)
        self.assertEqual(r2.returncode, 0)
        # The audit line legitimately differs (each run appends, seq increments);
        # the *simulation report* must be byte-identical.
        body = lambda r: [l for l in r.stdout.splitlines() if "recorded to audit store" not in l]
        self.assertEqual(body(r1), body(r2))

    def test_seir_default_green(self):
        r = run_cli(["seir", "--days", "45"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SEIR model", r.stdout)
        self.assertIn("R0=3.00", r.stdout)
        self.assertIn("peak infected :", r.stdout)

    def test_sir_respects_model_equations(self):
        # Below threshold (R0 < 1) the infection must not grow. This is the
        # fail-closed property: fewer than one secondary infection per host.
        r = run_cli(["sir", "--beta", "0.1", "--gamma", "0.2", "--i0", "50",
                     "--days", "45"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        peak = int(re.search(r"peak infected : (\d+)", r.stdout).group(1))
        self.assertLessEqual(peak, 50)

    # --- analytic anchor ----------------------------------------------------

    def test_compare_green_defaults(self):
        r = run_cli(["compare"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verdict: within tolerance", r.stdout)
        self.assertIn("max relative error:", r.stdout)

    def test_compare_fail_over_really_fails(self):
        # Negative control through the real CLI: push the comparison far
        # outside the linear window; the --fail-over gate MUST go red.
        r = run_cli(["compare", "--days", "60", "--step", "0.05",
                     "--fail-over", "--tol", "1e-6"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("diverged", r.stderr)
        self.assertIn("verdict: OUT OF TOLERANCE", r.stdout)

    # --- worst-case sweep ---------------------------------------------------

    def test_sweep_green(self):
        r = run_cli(["sweep", "--grid", "2"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("worst peak", r.stdout)
        self.assertIn("plan for", r.stdout)

    def test_sweep_worst_bounds_every_single_run(self):
        # Fail-closed planning: the envelope must be at least as pessimistic
        # as any single corner of the uncertainty box -- for the peak AND for
        # the final removal count.
        r = run_cli(["sweep", "--grid", "3", "--beta-min", "0.2", "--beta-max",
                     "0.4", "--gamma-min", "0.05", "--gamma-max", "0.15"],
                    store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        worst_peak = float(re.search(r"worst peak   : ([\d,]+)", r.stdout).group(1).replace(",", ""))
        worst_final = float(re.search(r"worst final  : ([\d,]+)", r.stdout).group(1).replace(",", ""))
        singles = []
        for b, g in ((0.2, 0.15), (0.4, 0.05), (0.3, 0.1)):
            s = run_cli(["sir", "--beta", str(b), "--gamma", str(g)],
                        store=self.store)
            peak = float(re.search(r"peak infected : ([\d,]+)", s.stdout).group(1).replace(",", ""))
            final_r = float(re.search(r"R=([\d,]+)", s.stdout).group(1).replace(",", ""))
            singles.append((peak, final_r))
        for pk, fr in singles:
            self.assertGreaterEqual(worst_peak, pk, f"envelope peak {worst_peak} below single-run {pk}")
            self.assertGreaterEqual(worst_final, fr, f"envelope final {worst_final} below single-run {fr}")

    # --- fail-closed input handling ----------------------------------------

    def test_invalid_i0_fails_closed(self):
        r = run_cli(["sir", "--i0", "999999"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot exceed N", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_negative_beta_fails_closed(self):
        r = run_cli(["sir", "--beta", "-0.5"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("beta must be > 0", r.stderr)

    def test_zero_beta_fails_closed(self):
        # A zero transmission rate is division-by-nonsense for the ODE; it must
        # be refused, not run as a degenerate model.
        r = run_cli(["sir", "--beta", "0"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("beta must be > 0", r.stderr)

    def test_unknown_command_exits_2(self):
        r = run_cli(["frobnicate"], store=self.store)
        self.assertEqual(r.returncode, 2)

    def test_version_flag(self):
        r = run_cli(["--version"], store=self.store)
        self.assertEqual(r.returncode, 0)
        self.assertIn("worm-lab 1.0.0", r.stdout)

    # --- audit trail --------------------------------------------------------

    def test_run_creates_audit_record(self):
        run_cli(["sir"], store=self.store)
        records = read_store(self.store)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["model"], "sir")
        self.assertEqual(records[0]["seq"], 0)
        self.assertEqual(len(records[0]["hash"]), 64)

    def test_verify_clean_after_runs(self):
        run_cli(["sir"], store=self.store)
        run_cli(["sir", "--beta", "0.4"], store=self.store)
        r = run_cli(["verify"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verified: 2 records, chain intact", r.stdout)

    def test_verify_empty_missing_store(self):
        r = run_cli(["verify"], store=self.store)
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing to verify", r.stdout)

    def test_verify_catches_middle_edit(self):
        run_cli(["sir"], store=self.store)
        run_cli(["seir"], store=self.store)
        run_cli(["sir"], store=self.store)
        with open(self.store, encoding="utf-8") as fh:
            data = fh.read()
        edited = data.replace('"version":"1.0.0"', '"version":"9.9.9"', 1)
        self.assertNotEqual(edited, data)
        with open(self.store, "w", encoding="utf-8") as fh:
            fh.write(edited)
        r = run_cli(["verify"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("TAMPERED", r.stdout)
        self.assertIn("hash does not match", r.stdout)

    def test_verify_catches_prefix_delete(self):
        run_cli(["sir"], store=self.store)
        run_cli(["sir"], store=self.store)
        with open(self.store, encoding="utf-8") as fh:
            lines = fh.readlines()
        with open(self.store, "w", encoding="utf-8") as fh:
            fh.writelines(lines[1:])
        r = run_cli(["verify"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("genesis anchor", r.stdout)

    def test_verify_catches_forged_insert(self):
        run_cli(["sir"], store=self.store)
        run_cli(["sir"], store=self.store)
        with open(self.store, encoding="utf-8") as fh:
            first = fh.readline()
            rest = fh.read()
        forged = {
            "seq": 1, "ts": 0.0, "tool": "worm-lab", "version": "9.9",
            "model": "sir", "params": {}, "metrics": {},
            "prev": "x" * 64, "hash": "y" * 64,
        }
        with open(self.store, "w", encoding="utf-8") as fh:
            fh.write(first)
            fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
            fh.write(rest)
        r = run_cli(["verify"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("TAMPERED", r.stdout)

    def test_run_refused_on_tampered_store(self):
        # Fail-closed: once the store no longer verifies, new runs must be
        # refused rather than silently appending to a broken chain.
        run_cli(["sir"], store=self.store)
        with open(self.store, encoding="utf-8") as fh:
            data = fh.read()
        with open(self.store, "w", encoding="utf-8") as fh:
            fh.write(data.replace('"version":"1.0.0"', '"version":"0.0.1"', 1))
        r = run_cli(["sir"], store=self.store)
        self.assertEqual(r.returncode, 1)
        self.assertIn("audit store does not verify", r.stderr)

    def test_env_store_location_respected(self):
        alt = os.path.join(self._td.name, "elsewhere", "run.jsonl")
        r = run_cli(["sir"], store=alt)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(alt))
        self.assertEqual(len(read_store(alt)), 1)

    def test_stats_lists_runs(self):
        run_cli(["sir"], store=self.store)
        run_cli(["seir"], store=self.store)
        r = run_cli(["stats"], store=self.store)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("#0", r.stdout)
        self.assertIn("#1", r.stdout)
        self.assertIn("sir", r.stdout)
        self.assertIn("seir", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)