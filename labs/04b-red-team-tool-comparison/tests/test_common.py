import unittest
from base64 import b64decode
from dataclasses import replace
from hashlib import sha256

from redteam_comparison.cases import (
    CORPUS_VERSION, build_benign_controls, build_common_corpus, corpus_sha256, select_phase_cases,
)
from redteam_comparison.oracle import evaluate


class CommonCorpusTests(unittest.TestCase):
    def test_v2_is_compact_varied_and_honestly_labelled(self):
        cases = build_common_corpus()
        base64_cases = [case for case in cases if case.vector == "encoding_base64"]
        indirect_cases = [case for case in cases if case.vector == "indirect_injection"]
        self.assertEqual(CORPUS_VERSION, "redteam-common-v2")
        self.assertEqual(len(base64_cases), 8)
        self.assertEqual(len(indirect_cases), 8)
        self.assertEqual({case.category for case in base64_cases}, {"instruction_following"})
        self.assertEqual(len({case.category for case in indirect_cases}), 8)
        decoded = [b64decode(case.message.rsplit(" ", 1)[1], validate=True).decode() for case in base64_cases]
        for case, payload in zip(base64_cases, decoded):
            self.assertIn(case.canary, payload)
            self.assertNotIn(case.canary, case.message)
        self.assertEqual(len({text.replace(case.canary, "TOKEN") for case, text in zip(base64_cases, decoded)}), 8)
        self.assertEqual(len({case.message.replace(case.canary, "TOKEN") for case in indirect_cases}), 8)
        self.assertEqual(len({case.case_id for case in cases + build_benign_controls()}), 24)
        self.assertEqual(len({case.canary for case in cases}), 16)
        self.assertTrue(all(case.canary in case.message for case in indirect_cases))

    def test_corpus_hash_is_stable(self):
        self.assertEqual(corpus_sha256(), corpus_sha256())
        self.assertEqual(corpus_sha256([]), sha256(b"").hexdigest())
        self.assertNotEqual(corpus_sha256(), corpus_sha256(build_common_corpus()[:1]))
        self.assertNotEqual(corpus_sha256(), corpus_sha256(list(reversed(build_common_corpus()))))

    def test_oracle_only_calls_explicit_evidence_a_result(self):
        case = build_common_corpus()[0]
        self.assertEqual(evaluate(case, "Solicitud bloqueada", False).outcome, "blocked")
        self.assertEqual(evaluate(case, case.canary, False).outcome, "attack_succeeded")
        self.assertEqual(evaluate(case, "No puedo ayudar.", False).outcome, "inconclusive")

    def test_canary_wins_over_block_flag_and_markers(self):
        case = build_common_corpus()[0]
        for blocked in (True, False):
            for response in (case.canary.lower(), "Solicitud bloqueada: " + case.canary):
                self.assertEqual(evaluate(case, response, blocked).outcome, "attack_succeeded")

    def test_oracle_rejects_invalid_inputs(self):
        case = build_common_corpus()[0]
        for response, blocked in ((None, False), ("", False), ("  ", False), ("ok", "false"), ("ok", 0)):
            with self.assertRaises(ValueError):
                evaluate(case, response, blocked)
        for invalid in (replace(case, canary=""), replace(case, expected="unknown")):
            with self.assertRaises(ValueError):
                evaluate(invalid, "ok", False)

    def test_phase_sample_and_bounds(self):
        cases = select_phase_cases(per_vector=3, benign_controls=2)
        self.assertEqual(len(cases), 8)
        self.assertEqual(sum(case.vector == "encoding_base64" for case in cases), 3)
        self.assertEqual(sum(case.vector == "indirect_injection" for case in cases), 3)
        self.assertEqual(sum(case.vector == "benign_control" for case in cases), 2)
        for count in (-1, 0, 9, True, 1.5):
            with self.assertRaises(ValueError):
                select_phase_cases(count)
        for count in (-1, 9, True, 1.5):
            with self.assertRaises(ValueError):
                build_benign_controls(count)

    def test_controls_are_unique_self_contained_and_non_attacks(self):
        controls = build_benign_controls()
        self.assertEqual(len({case.message for case in controls}), 8)
        self.assertTrue(all(not case.canary and case.expected == "must_not_block" for case in controls))
        self.assertIn("vendimos 12 libros", controls[0].message)
        self.assertTrue(any("Base64" in case.message for case in controls))
        for case in controls:
            self.assertEqual(evaluate(case, "Respuesta de prueba", False).outcome, "allowed")

    def test_oracle_marks_a_blocked_control_as_false_positive(self):
        control = select_phase_cases(per_vector=1, benign_controls=1)[-1]
        self.assertEqual(evaluate(control, "Solicitud bloqueada", True).outcome, "false_positive")


if __name__ == "__main__":
    unittest.main()
