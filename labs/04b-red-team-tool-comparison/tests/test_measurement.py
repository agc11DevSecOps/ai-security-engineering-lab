"""Offline measurement contracts; every HTTP entry point is mocked."""
import copy
import fcntl
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from redteam_comparison.oracle import validate_target
from scripts import analyze_results as analyzer
from scripts import run_target_corpus as runner


TARGET = {"response": "Respuesta sintetica", "blocked": False, "blocked_at_layer": None, "details": {}}


class TargetSchemaTests(unittest.TestCase):
    def test_required_fields_and_types(self):
        invalid = [None, [], "text", 1, {}]
        for key in TARGET:
            item = dict(TARGET)
            del item[key]
            invalid.append(item)
        for key, values in {
            "response": [None, [], {}, 0, False, "", "  "],
            "blocked": [None, "false", "true", 0, 1, []],
            "blocked_at_layer": ["prompt_guard", 1, False, []],
            "details": [None, [], "text"],
        }.items():
            invalid.extend({**TARGET, key: value} for value in values)
        invalid.extend({**TARGET, "blocked": True, "blocked_at_layer": layer} for layer in (None, "", " ", 1))
        for target in invalid:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target)
        self.assertEqual(validate_target(TARGET), TARGET)
        self.assertTrue(validate_target({**TARGET, "blocked": True, "blocked_at_layer": "prompt_guard"})["blocked"])

    def test_nested_filter_evidence_is_not_coerced(self):
        for output in (None, [], "text", {"pii_check": None}, {"pii_check": {}},
                       {"pii_check": {"entities_found": [1]}},
                       {"system_prompt_leak_check": {"leaked": "false"}},
                       {"forbidden_keywords_check": {"matched_keywords": "word"}}):
            with self.subTest(output=output), self.assertRaises(ValueError):
                runner.filter_reasons({**TARGET, "details": {"output_check": output}})
        target = {**TARGET, "details": {"output_check": {
            "pii_check": {"entities_found": ["EMAIL_ADDRESS"]},
            "system_prompt_leak_check": {"leaked": False},
            "forbidden_keywords_check": {"matched_keywords": ["synthetic"]},
        }}}
        self.assertEqual(runner.filter_reasons(target), {
            "pii_entities": ["EMAIL_ADDRESS"], "system_prompt_leak": False,
            "forbidden_keywords": ["synthetic"],
        })

    def test_http_request_and_strict_json(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch.object(runner, "urlopen", return_value=response) as opening:
            response.read.return_value = json.dumps(TARGET).encode()
            self.assertEqual(runner.call_target("http://example.invalid/chat", "hola", 3), TARGET)
            request = opening.call_args.args[0]
            self.assertEqual(json.loads(request.data), {"message": "hola"})
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(opening.call_args.kwargs["timeout"], 3)
            for raw in (b"{", b"[]", b"null", b'\xff', b'{"blocked":false,"blocked":true}', b'{"x":NaN}'):
                response.read.return_value = raw
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    runner.call_target("http://example.invalid/chat", "hola", 3)


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.report = Path(temporary.name) / "run.jsonl"
        self.manifest = runner.manifest_path(self.report)
        self.args = ["--tool", "offline-test", "--output", str(self.report), "--per-vector", "2",
                     "--benign-controls", "2", "--pause", "0.25"]
        self.addCleanup(patch.stopall)
        patch.object(runner, "urlopen", side_effect=AssertionError("network forbidden")).start()
        self.target = patch.object(runner, "call_target", return_value=TARGET).start()
        self.sleep = patch.object(runner.time, "sleep").start()
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.out_context = redirect_stdout(self.stdout)
        self.err_context = redirect_stderr(self.stderr)
        self.out_context.__enter__()
        self.err_context.__enter__()
        self.addCleanup(self.out_context.__exit__, None, None, None)
        self.addCleanup(self.err_context.__exit__, None, None, None)

    def write_records(self, records):
        self.report.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")

    def write_manifest(self, manifest):
        self.manifest.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    def incomplete(self):
        self.sleep.side_effect = KeyboardInterrupt
        self.assertEqual(runner.main(self.args), 130)
        self.sleep.side_effect = None
        self.target.reset_mock()

    def test_complete_report_manifest_and_analysis(self):
        self.assertEqual(runner.main(self.args), 0)
        manifest, records, _ = runner.read_run(self.report)
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["producer"], "common-http")
        self.assertEqual(len(records), 6)
        self.assertEqual(manifest["expected_ids"], [item["case"]["case_id"] for item in records])
        self.assertEqual(self.sleep.call_count, 6)
        self.sleep.assert_called_with(0.25)
        self.assertEqual(analyzer.main([str(self.report)]), 0)
        self.assertIn("complete=True expected=6 missing=0", self.stdout.getvalue())
        self.assertIn("inconclusive=100.00%", self.stdout.getvalue())
        self.assertIn("allowed=100.00%", self.stdout.getvalue())

    def test_canary_with_block_is_scored_as_success_end_to_end(self):
        case = runner.select_cases(per_vector=2)[0]
        self.target.return_value = {**TARGET, "response": "Solicitud bloqueada " + case.canary,
                                    "blocked": True, "blocked_at_layer": "prompt_guard"}
        self.assertEqual(runner.main(self.args), 0)
        _, records, _ = runner.read_run(self.report)
        self.assertEqual(records[0]["verdict"]["outcome"], "attack_succeeded")

    def test_no_overwrite_even_on_resume_of_complete_run(self):
        self.assertEqual(runner.main(self.args), 0)
        original = self.report.read_bytes(), self.manifest.read_bytes()
        self.target.reset_mock()
        for extra in ([], ["--resume"]):
            self.assertEqual(runner.main(self.args + extra), 1)
            self.assertEqual((self.report.read_bytes(), self.manifest.read_bytes()), original)
        self.target.assert_not_called()

    def test_manifest_alone_also_prevents_overwrite(self):
        self.manifest.write_text("historical", encoding="utf-8")
        self.assertEqual(runner.main(self.args), 1)
        self.assertFalse(self.report.exists())
        self.target.assert_not_called()

    def test_resume_valid_prefix_without_repeating_durable_requests(self):
        self.incomplete()
        prefix = self.report.read_bytes()
        self.assertEqual(runner.main(self.args + ["--resume"]), 0)
        self.assertTrue(self.report.read_bytes().startswith(prefix))
        self.assertEqual(self.target.call_count, 5)
        self.assertEqual(analyzer.main([str(self.report)]), 0)

    def test_last_record_durable_before_completion_can_be_finalized(self):
        self.sleep.side_effect = [None] * 5 + [KeyboardInterrupt()]
        self.assertEqual(runner.main(self.args), 130)
        self.assertEqual(analyzer.main([str(self.report)]), 1)
        self.target.reset_mock()
        self.assertEqual(runner.main(self.args + ["--resume"]), 0)
        self.target.assert_not_called()

    def test_resume_rejects_mismatched_configuration(self):
        self.incomplete()
        original = self.report.read_bytes(), self.manifest.read_bytes()
        for option in (["--tool", "other"], ["--url", "http://example.invalid/chat"],
                       ["--timeout", "8"], ["--pause", "0"], ["--per-vector", "1"]):
            self.assertEqual(runner.main(self.args + option + ["--resume"]), 1)
            self.assertEqual((self.report.read_bytes(), self.manifest.read_bytes()), original)
        self.target.assert_not_called()

    def test_concurrent_resume_is_refused(self):
        self.incomplete()
        with self.report.open("rb") as report:
            fcntl.flock(report.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(runner.main(self.args + ["--resume"]), 1)
        self.target.assert_not_called()

    def test_records_are_flushed_and_synced_before_pause(self):
        real_fsync = runner.os.fsync
        with patch.object(runner.os, "fsync", wraps=real_fsync) as synced:
            def pause(_):
                _, records, _ = runner.read_run(self.report)
                self.assertEqual(len(records), self.target.call_count)
                self.assertGreaterEqual(synced.call_count, len(records) + 3)
            self.sleep.side_effect = pause
            self.assertEqual(runner.main(self.args), 0)

    def test_errors_are_durable_nonzero_and_excluded_from_rates(self):
        self.target.side_effect = [
            HTTPError("http://example.invalid", 503, "offline", {}, None), URLError("offline"),
            TimeoutError("offline"), IncompleteRead(b"partial"), ValueError("malformed JSON"),
            {**TARGET, "blocked": "false"},
        ]
        self.assertEqual(runner.main(self.args), 1)
        manifest, records, _ = runner.read_run(self.report)
        self.assertEqual(manifest["error_count"], 6)
        self.assertEqual(self.sleep.call_count, 6)
        self.assertTrue(all("error" in item and "verdict" not in item for item in records))
        self.assertEqual(analyzer.main([str(self.report)]), 1)
        self.assertIn("complete=True", self.stdout.getvalue())
        self.assertNotIn("attack_rates", self.stdout.getvalue())
        self.assertIn("rates_suppressed", self.stdout.getvalue())
        self.assertIn("'encoding_base64': 2", self.stdout.getvalue())

    def test_resume_preserves_errors_without_retrying_or_hiding_them(self):
        self.target.side_effect = TimeoutError("offline")
        self.incomplete()
        self.target.side_effect = None
        self.assertEqual(runner.main(self.args + ["--resume"]), 1)
        manifest, _, _ = runner.read_run(self.report)
        self.assertEqual(manifest["error_count"], 1)
        self.assertEqual(self.target.call_count, 5)

    def test_empty_and_partial_runs_never_report_complete(self):
        self.target.side_effect = KeyboardInterrupt
        self.assertEqual(runner.main(self.args), 130)
        self.assertEqual(analyzer.main([str(self.report)]), 1)
        self.assertIn("complete=False expected=6 missing=6", self.stdout.getvalue())
        self.assertIn("unavailable", self.stdout.getvalue())
        self.assertNotIn("attack_rates", self.stdout.getvalue())

    def test_missing_manifest_does_not_rewrite_historical_report(self):
        self.report.write_text('{"corpus_version":"redteam-common-v1"}\n', encoding="utf-8")
        original = self.report.read_bytes()
        self.assertEqual(analyzer.main([str(self.report)]), 1)
        self.assertEqual(runner.main(self.args + ["--resume"]), 1)
        self.assertEqual(self.report.read_bytes(), original)
        self.assertIn("legacy or unverified", self.stderr.getvalue())
        self.target.assert_not_called()

    def test_corrupt_or_truncated_prefix_is_never_repaired_or_resumed(self):
        self.incomplete()
        original = self.report.read_bytes()
        for data in (original[:-1], original + b'{"broken":', original + b"\n", b"\xff\n", b"[]\n"):
            with self.subTest(data=data):
                self.report.write_bytes(data)
                self.assertEqual(runner.main(self.args + ["--resume"]), 1)
                self.assertEqual(analyzer.main([str(self.report)]), 1)
                self.assertEqual(self.report.read_bytes(), data)
        self.target.assert_not_called()

    def test_integrity_rejects_duplicates_missing_reordering_mixed_hash_and_bad_schema(self):
        self.assertEqual(runner.main(self.args), 0)
        manifest, records, _ = runner.read_run(self.report)
        variants = [records[:-1], records[1:], records + [records[0]],
                    [records[0], records[0]] + records[2:], list(reversed(records))]
        for field, value in (("corpus_sha256", "wrong"), ("run_id", "other"), ("tool", "other"),
                             ("producer", "garak"), ("corpus_version", "v1"), ("elapsed_ms", -1),
                             ("elapsed_ms", True), ("elapsed_ms", float("nan")),
                             ("response", []), ("blocked", "false"), ("timestamp", None),
                             ("verdict", {"outcome": "blocked"}), ("error", "conflicting"),
                             ("filter_reasons", {})):
            variant = copy.deepcopy(records)
            variant[0][field] = value
            variants.append(variant)
        variant = copy.deepcopy(records)
        variant[0]["case"]["message"] += "tampered"
        variants.append(variant)
        # Same oracle outcome, different response: only the report digest catches this.
        variant = copy.deepcopy(records)
        variant[0]["response"] = "Different non-canary answer"
        variants.append(variant)
        for index, variant in enumerate(variants):
            with self.subTest(index=index):
                self.write_records(variant)
                self.assertEqual(analyzer.main([str(self.report)]), 1)
        self.write_records(records)
        # Writing equivalent JSON preserved the serialization used by the runner.
        self.assertEqual(runner.read_run(self.report)[0], manifest)

    def test_manifest_integrity_and_completion_fields(self):
        self.assertEqual(runner.main(self.args), 0)
        manifest, _, _ = runner.read_run(self.report)
        for field, value in (("expected_ids", []), ("corpus_sha256", "wrong"),
                             ("report_sha256", "wrong"), ("record_count", 1), ("error_count", 1),
                             ("status", "running"), ("completed_at", None),
                             ("selection", {}), ("format_version", 1), ("pause", -1)):
            with self.subTest(field=field):
                self.write_manifest({**manifest, field: value})
                self.assertEqual(analyzer.main([str(self.report)]), 1)
        for raw in ("{", "[]", '{"format_version":2,"format_version":2}'):
            self.manifest.write_text(raw, encoding="utf-8")
            self.assertEqual(analyzer.main([str(self.report)]), 1)

    def test_invalid_selection_and_timing_never_send_requests(self):
        for options in (["--limit", "-1"], ["--per-vector", "-1"], ["--per-vector", "9"],
                        ["--benign-controls", "-1"], ["--benign-controls", "9"],
                        ["--limit", "99", "--per-vector", "0"], ["--limit", "1"],
                        ["--controls-only"], ["--pause", "nan"], ["--pause", "-1"],
                        ["--pause", "inf"], ["--timeout", "0"], ["--timeout", "nan"],
                        ["--timeout", "inf"]):
            with self.subTest(options=options):
                self.assertEqual(runner.main(self.args + options), 1)
                self.assertFalse(self.report.exists())
        self.target.assert_not_called()

    def test_vector_and_controls_only_selection(self):
        cases = runner.select_cases(vector="indirect_injection", limit=3, benign_controls=2)
        self.assertEqual([case.vector for case in cases], ["indirect_injection"] * 3 + ["benign_control"] * 2)
        self.assertEqual(len(runner.select_cases(controls_only=True, benign_controls=8)), 8)
        self.assertEqual(len(runner.select_cases()), 16)
        self.assertEqual(len(runner.select_cases(benign_controls=8)), 24)
        for config in ({"vector": "other"}, {"vector": "encoding_base64", "limit": 9},
                       {"controls_only": True}, {"controls_only": True, "benign_controls": 1, "vector": "encoding_base64"}):
            with self.assertRaises(ValueError):
                runner.select_cases(**config)


if __name__ == "__main__":
    unittest.main()
