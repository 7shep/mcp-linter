"""Tests for benchmark/agentdojo_score.py.

THREAT MODEL
  DEFENDS AGAINST: the scorer silently reporting a success rate from incomplete,
    duplicated or mistyped trial logs (a missing trial read as a failed attack,
    a conflicting id read as a valid trial), errored trials counted as failures,
    or AgentDojo's messages and injected text copied into committed outputs.
  ATTACKER CONTROLS: the content of a trial log file in the run directory (for
    example, a crafted id, a non-bool field, or attack text in a message).
  MUST FAIL CLOSED WHEN: an id is not in cases.json, a trial's fields disagree
    with its path, a bool field is not a bool, an expected trial is missing
    without --allow-partial, or more than one pipeline directory is present with
    --pipeline unset. Each exits 2 and writes nothing.
  OUT OF SCOPE: whether AgentDojo's security check is itself correct, and whether
    the tagger's labels are right (both reviewed elsewhere).
"""

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS_DIR)
BENCH = os.path.join(REPO, "benchmark")
if BENCH not in sys.path:
    sys.path.insert(0, BENCH)

import agentdojo_crosscheck as xc  # noqa: E402
import agentdojo_score as sc  # noqa: E402

SCORE_SRC = os.path.join(BENCH, "agentdojo_score.py")
ATTACK = "important_instructions"
SENTINEL = "SENTINEL-DO-NOT-COPY-7f3a91"
CASES = xc._load_json(xc.CASES_PATH)
KINDS = xc._load_json(xc.KINDS_PATH)
LABELS = sc.build_labels(CASES, KINDS)
ATTACKED_KEYS = [(s, u, i) for s, v in CASES["suites"].items()
                 for u in v["user_tasks"] for i in v["injection_tasks"]]
USER_TASKS = [(s, u) for s, v in CASES["suites"].items() for u in v["user_tasks"]]
CASES_SUITE = next(iter(CASES["suites"]))
CASES_USER = next(iter(CASES["suites"][CASES_SUITE]["user_tasks"]))


def _doc(suite, uid, iid, attack, utility, security, error):
    """A trial log shaped like AgentDojo's, with the attack text in messages and injections."""
    return {
        "suite_name": suite,
        "user_task_id": uid,
        "injection_task_id": iid,
        "attack_type": attack,
        "utility": utility,
        "security": security,
        "error": error,
        "messages": [{"role": "assistant", "content": SENTINEL}],
        "injections": {"injection_bill_text": SENTINEL},
    }


def _write_doc(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)


def write_run(root, pipeline="fake-model", attack=ATTACK, *, attacked=None, clean=True,
              clean_utility=True, skip=()):
    """Write a full fake log tree. ``attacked`` maps a key to (utility, security, error)."""
    pdir = os.path.join(root, pipeline)
    for suite, uid, iid in ATTACKED_KEYS:
        if (suite, uid, iid) in skip:
            continue
        util, sec, err = attacked((suite, uid, iid)) if attacked else (True, False, None)
        _write_doc(os.path.join(pdir, suite, uid, attack, iid + ".json"),
                   _doc(suite, uid, iid, attack, util, sec, err))
    if clean:
        for suite, uid in USER_TASKS:
            _write_doc(os.path.join(pdir, suite, uid, "none", "none.json"),
                       _doc(suite, uid, None, None, clean_utility, False, None))
    return pdir


def run_cli(run_dir, out_dir, *extra, attack=ATTACK):
    argv = [run_dir, "--attack", attack, "--out-dir", out_dir, *extra]
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sc.main(argv)
    return rc, out.getvalue(), err.getvalue()


def load_out(out_dir, name="fake-model"):
    with open(os.path.join(out_dir, f"asr_{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def exfil_keys():
    return [k for k in ATTACKED_KEYS if LABELS[("v1", "strict")][k]["kind"] == "exfil"]


class LabelTests(unittest.TestCase):
    def test_v1_path_counts_match_crosscheck(self):
        for profile, expected in (("strict", 83), ("inclusive", 123)):
            table = LABELS[("v1", profile)]
            exfil = [v for v in table.values() if v["kind"] == "exfil"]
            self.assertEqual(len(exfil), 582)
            self.assertEqual(sum(v["path_covered"] for v in exfil), expected, profile)


class ScoreMathTests(unittest.TestCase):
    def test_wilson_and_rate_are_null_for_zero_denominator(self):
        block = sc.rate(0, 0)
        self.assertIsNone(block["rate"])
        self.assertIsNone(block["wilson95"])

    def test_bootstrap_undefined_when_one_side_has_no_cases(self):
        units = {"workspace": [(0, 0, 3, 1), (0, 0, 2, 0)]}
        result = sc.bootstrap_difference(units, reps=50)
        self.assertIsNone(result["value"])
        self.assertIsNone(result["ci95"])
        self.assertEqual(result["defined_reps"], 0)

    def test_bootstrap_units_are_user_tasks_across_suites(self):
        units = {s: [(1, 1, 1, 0)] * n for s, n in (("a", 3), ("b", 2))}
        result = sc.bootstrap_difference(units, reps=20)
        self.assertEqual(result["units"], 5)

    def test_script_does_not_import_agentdojo(self):
        with open(SCORE_SRC, encoding="utf-8") as f:
            src = f.read()
        self.assertIsNone(re.search(r"^\s*(import|from)\s+agentdojo\b", src, re.M))


class ScoreCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.out = os.path.join(self.root, "out")

    def tearDown(self):
        self._tmp.cleanup()

    def test_all_attacks_succeed_gives_asr_one_and_standard_precision_recall(self):
        run = write_run(os.path.join(self.root, "runs"), attacked=lambda k: (True, True, None))
        rc, _, err = run_cli(os.path.dirname(run), self.out)
        self.assertEqual(rc, 0, err)
        cell = load_out(self.out)["cells"]["v1/strict"]
        self.assertEqual(cell["exfil_path_labelled"]["rate"], 1.0)
        self.assertEqual(cell["exfil_path_unlabelled"]["rate"], 1.0)
        self.assertEqual(cell["predictor"]["precision"]["n"], 83)
        self.assertEqual(cell["predictor"]["precision"]["rate"], 1.0)
        self.assertEqual(cell["predictor"]["recall"]["n"], 582)
        self.assertEqual(cell["predictor"]["recall"]["rate"], 83 / 582)

    def test_all_attacks_fail_gives_asr_zero_and_undefined_recall(self):
        run = write_run(os.path.join(self.root, "runs"), attacked=lambda k: (True, False, None))
        rc, _, err = run_cli(os.path.dirname(run), self.out)
        self.assertEqual(rc, 0, err)
        cell = load_out(self.out)["cells"]["v1/strict"]
        self.assertEqual(cell["exfil_path_labelled"]["rate"], 0.0)
        self.assertEqual(cell["exfil_path_unlabelled"]["rate"], 0.0)
        self.assertEqual(cell["predictor"]["precision"]["rate"], 0.0)
        self.assertEqual(cell["predictor"]["precision"]["n"], 83)
        self.assertIsNone(cell["predictor"]["recall"]["rate"])
        self.assertIsNone(cell["predictor"]["recall"]["wilson95"])

    def test_missing_trial_exit_2_then_partial_with_flag(self):
        runs = os.path.join(self.root, "runs")
        run = write_run(runs, skip={ATTACKED_KEYS[0]})
        rc, _, err = run_cli(os.path.dirname(run), self.out)
        self.assertEqual(rc, 2)
        self.assertIn("1 of 1046 expected trials are missing", err)
        rc, _, err = run_cli(os.path.dirname(run), self.out, "--allow-partial")
        self.assertEqual(rc, 0, err)
        report = load_out(self.out)
        self.assertTrue(report["partial"])
        self.assertEqual(report["trials"]["missing"], 1)

    def test_same_ids_under_two_attack_dirs_are_not_duplicates(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs, attack=ATTACK)
        pdir = write_run(runs, attack="other_attack", clean=False)
        self.assertTrue(os.path.isdir(os.path.join(pdir, CASES_SUITE, CASES_USER, "other_attack")))
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 0, err)

    def test_two_pipelines_without_pipeline_flag_exit_2(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs, pipeline="pipe_a")
        write_run(runs, pipeline="pipe_b")
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 2)
        self.assertIn("2 pipeline directories", err)
        rc, _, err = run_cli(runs, self.out, "--pipeline", "pipe_a")
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.isfile(os.path.join(self.out, "asr_pipe_a.json")))

    def test_trial_whose_ids_disagree_with_its_path_exit_2(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs)
        bad = os.path.join(runs, "fake-model", CASES_SUITE, CASES_USER, ATTACK,
                           "injection_task_1.json")
        _write_doc(bad, _doc(CASES_SUITE, CASES_USER, "injection_task_0", ATTACK, True, False, None))
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 2)
        self.assertIn("injection_task_id does not match the path", err)

    def test_errored_trial_excluded_from_denominators_and_counted(self):
        runs = os.path.join(self.root, "runs")
        target = exfil_keys()[0]
        write_run(runs, attacked=lambda k: (False, False, "boom") if k == target else (True, True, None))
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 0, err)
        report = load_out(self.out)
        self.assertEqual(report["trials"]["errored"], 1)
        cell = report["cells"]["v1/strict"]
        n = cell["exfil_path_labelled"]["n"] + cell["exfil_path_unlabelled"]["n"]
        succ = (cell["exfil_path_labelled"]["successes"] + cell["exfil_path_unlabelled"]["successes"])
        self.assertEqual(n, 581)
        self.assertEqual(succ, 581)
        errored_rows = [r for r in report["attacked"] if r["outcome"] == "errored"]
        self.assertEqual(len(errored_rows), 1)

    def test_unknown_user_task_exit_2(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs)
        _write_doc(os.path.join(runs, "fake-model", CASES_SUITE, "user_task_999", ATTACK,
                                "injection_task_0.json"),
                   _doc(CASES_SUITE, "user_task_999", "injection_task_0", ATTACK, True, False, None))
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 2)
        self.assertIn("user task is not in cases.json", err)

    def test_non_bool_security_exit_2(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs)
        bad = os.path.join(runs, "fake-model", *ATTACKED_KEYS[3][:2], ATTACK,
                           ATTACKED_KEYS[3][2] + ".json")
        _write_doc(bad, _doc(*ATTACKED_KEYS[3], ATTACK, True, "true", None))
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 2)
        self.assertIn("security is not a bool", err)

    def test_sentinel_text_never_reaches_outputs(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs, attacked=lambda k: (True, True, None))
        rc, out_text, err = run_cli(runs, self.out)
        self.assertEqual(rc, 0, err)
        for name in ("asr_fake-model.json", "asr_fake-model.md"):
            with open(os.path.join(self.out, name), encoding="utf-8") as f:
                self.assertNotIn(SENTINEL, f.read(), name)
        self.assertNotIn(SENTINEL, out_text + err)

    def test_bootstrap_resamples_all_97_user_tasks(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs)
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 0, err)
        report = load_out(self.out)
        self.assertEqual(len(USER_TASKS), 97)
        self.assertEqual(report["bootstrap"]["units"], 97)
        self.assertEqual(report["bootstrap"]["unit"], "user_task")
        self.assertEqual(report["bootstrap"]["reps"], 2000)

    def test_clean_and_attacked_utility_are_separate(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs, attacked=lambda k: (False, False, None), clean_utility=True)
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 0, err)
        measures = load_out(self.out)["measures"]
        self.assertEqual(measures["clean_utility"]["rate"], 1.0)
        self.assertEqual(measures["utility_under_attack"]["rate"], 0.0)

    def test_output_name_is_sanitised(self):
        runs = os.path.join(self.root, "runs")
        write_run(runs, pipeline="Fake Model!")
        rc, _, err = run_cli(runs, self.out)
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.isfile(os.path.join(self.out, "asr_fake_model_.json")))


if __name__ == "__main__":
    unittest.main()
