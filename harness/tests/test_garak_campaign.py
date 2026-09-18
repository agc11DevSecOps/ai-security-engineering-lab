"""Offline campaign manifests must fail closed before Garak can run."""

import json
# Tests inject subprocess outcomes and never run a command.
import subprocess  # nosec B404
import tempfile
import unittest
from pathlib import Path

from core.garak_campaign import (
    CampaignManifestError,
    GarakRunError,
    GarakRunStatus,
    OfflineGarakRunner,
    StagingGarakRunner,
    load_offline_campaign,
    load_staging_campaign,
)


class OfflineCampaignTests(unittest.TestCase):
    def write_manifest(self, payload: dict[str, object]) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "campaign.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def manifest() -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": "approved-offline",
            "campaign_id": "garak-offline-smoke",
            "reviewer": "security-reviewer",
            "mode": "offline",
            "generator": "test.Blank",
            "target": None,
            "network_authorization": None,
            "probes": ["encoding.InjectBase64"],
            "request_budget": 1,
            "timeout_seconds": 30,
            "concurrency": 1,
            "allow_raw_evidence": False,
        }

    def test_loads_a_bounded_offline_campaign(self) -> None:
        campaign = load_offline_campaign(self.write_manifest(self.manifest()))

        self.assertEqual(campaign.generator, "test.Blank")
        self.assertEqual(campaign.request_budget, 1)

    def test_rejects_any_target_or_network_authorization(self) -> None:
        for key, value in (
            ("target", "http://127.0.0.1:8000/chat"),
            ("network_authorization", {"host": "127.0.0.1"}),
        ):
            payload = self.manifest()
            payload[key] = value
            with self.assertRaisesRegex(CampaignManifestError, "campaign-network-not-allowed"):
                load_offline_campaign(self.write_manifest(payload))

    def test_rejects_unapproved_generator_and_unbounded_settings(self) -> None:
        for key, value in (
            ("status", "approved"),
            ("generator", "rest.RestGenerator"),
            ("request_budget", 101),
            ("concurrency", 2),
            ("allow_raw_evidence", True),
        ):
            payload = self.manifest()
            payload[key] = value
            with self.assertRaises(CampaignManifestError):
                load_offline_campaign(self.write_manifest(payload))

    def test_rejects_non_test_probes_and_a_budget_smaller_than_probe_count(self) -> None:
        for probes, budget in ((["dan.DAN"], 1), (["test.Blank", "test.Repeat"], 1)):
            payload = self.manifest()
            payload["probes"] = probes
            payload["request_budget"] = budget
            with self.subTest(probes=probes, budget=budget):
                with self.assertRaises(CampaignManifestError):
                    load_offline_campaign(self.write_manifest(payload))


class OfflineGarakRunnerTests(OfflineCampaignTests):
    def test_runs_only_test_generators_with_bounded_safe_argv_and_summary(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def process_runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
            calls.append((argv, kwargs))
            prefix = Path(argv[argv.index("--report_prefix") + 1])
            prefix.with_suffix(".report.jsonl").write_text(
                '\n'.join(
                    (
                        '{"entry_type":"attempt","prompt":"secret prompt","outputs":["secret response"]}',
                        '{"entry_type":"eval","total_evaluated":1,"fails":0}',
                        '{"entry_type":"completion"}',
                    )
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(argv, 0)

        result = OfflineGarakRunner(Path("/reviewed/bin/garak"), process_runner).run(
            self.write_manifest(self.manifest())
        )

        self.assertEqual(result.status, GarakRunStatus.COMPLETED)
        self.assertEqual(result.summary.attempt_count, 1)
        self.assertEqual(result.summary.failure_count, 0)
        self.assertEqual(result.summary.hit_count, 0)
        self.assertIsNone(result.error)
        argv, kwargs = calls[0]
        self.assertEqual(
            argv[:9],
            [
                "/reviewed/bin/garak",
                "--target_type",
                "test.Blank",
                "--probes",
                "encoding.InjectBase64",
                "--generations",
                "1",
                "--parallel_requests",
                "1",
            ],
        )
        self.assertIn("--report_prefix", argv)
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"]["HTTP_PROXY"], "")
        self.assertEqual(kwargs["env"]["NO_PROXY"], "*")
        self.assertNotIn("secret prompt", repr(result))
        self.assertNotIn("secret response", repr(result))
        report_prefix = Path(argv[argv.index("--report_prefix") + 1])
        self.assertEqual(report_prefix.parent, Path(kwargs["cwd"]))
        self.assertFalse(report_prefix.parent.exists())

    def test_revalidates_the_manifest_before_invoking_the_process(self) -> None:
        payload = self.manifest()
        payload["generator"] = "rest.RestGenerator"
        invoked = False

        def process_runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[object]:
            nonlocal invoked
            invoked = True
            return subprocess.CompletedProcess([], 0)

        result = OfflineGarakRunner(Path("/reviewed/bin/garak"), process_runner).run(
            self.write_manifest(payload)
        )

        self.assertEqual(result.status, GarakRunStatus.INCOMPLETE)
        self.assertEqual(result.error, GarakRunError.INVALID_REPORT)
        self.assertFalse(invoked)

    def test_missing_executable_timeout_and_bad_exit_are_typed_incomplete_results(self) -> None:
        cases = (
            (FileNotFoundError(), GarakRunError.EXECUTABLE_UNAVAILABLE),
            (subprocess.TimeoutExpired(["garak"], 30), GarakRunError.TIMEOUT),
            (subprocess.CompletedProcess([], 2), GarakRunError.BAD_EXIT),
        )
        for outcome, error in cases:
            def process_runner(*_args: object, outcome: object = outcome, **_kwargs: object) -> object:
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

            with self.subTest(error=error):
                result = OfflineGarakRunner(Path("/reviewed/bin/garak"), process_runner).run(
                    self.write_manifest(self.manifest())
                )
                self.assertEqual(result.status, GarakRunStatus.INCOMPLETE)
                self.assertEqual(result.error, error)
                self.assertIsNone(result.summary)

    def test_missing_or_unsafe_report_is_typed_incomplete(self) -> None:
        reports = (
            None,
            '{"entry_type":"eval","total_evaluated":1,"fails":0,"prompt":"raw"}\n{"entry_type":"completion"}',
            '{"entry_type":"eval","total_evaluated":2,"fails":0}\n{"entry_type":"completion"}',
            '{"entry_type":"eval","total_evaluated":true,"fails":0}\n{"entry_type":"completion"}',
        )
        for report in reports:
            def process_runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[object]:
                if report is not None:
                    prefix = Path(argv[argv.index("--report_prefix") + 1])
                    prefix.with_suffix(".report.jsonl").write_text(report, encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0)

            with self.subTest(report=report):
                result = OfflineGarakRunner(Path("/reviewed/bin/garak"), process_runner).run(
                    self.write_manifest(self.manifest())
                )
                self.assertEqual(result.status, GarakRunStatus.INCOMPLETE)
                self.assertEqual(result.error, GarakRunError.INVALID_REPORT)

    def test_requires_a_fixed_absolute_executable_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute"):
            OfflineGarakRunner(Path("garak"))


class StagingCampaignTests(OfflineCampaignTests):
    @staticmethod
    def staging_manifest() -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": "approved",
            "campaign_id": "garak-synthetic-staging-smoke-v1",
            "owner": "Alberto Galan",
            "reviewer": "Alberto Galan",
            "target": {"scheme": "http", "host": "127.0.0.1", "port": 8088, "path": "/chat"},
            "window_minutes": 15,
            "approved_at": "2026-09-07T18:05:00-04:00",
            "request_budget": 10,
            "timeout_seconds": 90,
            "concurrency": 1,
            "generator": "rest.RestGenerator",
            "probes": ["encoding.InjectBase64"],
            "credentials": "none",
            "allow_raw_evidence": False,
            "network_authorization": True,
            "approval": {"c1": "approved by Alberto Galan on 2026-09-07", "c2": "approved by Alberto Galan on 2026-09-07"},
        }

    def test_loads_the_exact_approved_staging_campaign(self) -> None:
        campaign = load_staging_campaign(self.write_manifest(self.staging_manifest()))

        self.assertEqual(campaign.target.host, "127.0.0.1")
        self.assertEqual(campaign.target.port, 8088)
        self.assertEqual(campaign.generator, "rest.RestGenerator")
        self.assertEqual(campaign.probes, ("encoding.InjectBase64",))

    def test_rejects_any_other_target_host_port_or_path(self) -> None:
        for key, value in (
            ("host", "localhost"),
            ("host", "example.com"),
            ("port", 8000),
            ("path", "/"),
            ("path", "/admin"),
        ):
            payload = self.staging_manifest()
            payload["target"][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(CampaignManifestError, "campaign-target-not-allowed"):
                    load_staging_campaign(self.write_manifest(payload))

    def test_rejects_unapproved_network_credentials_and_generator(self) -> None:
        for key, value in (
            ("status", "draft"),
            ("network_authorization", False),
            ("credentials", "token"),
            ("generator", "test.Blank"),
            ("allow_raw_evidence", True),
            ("concurrency", 2),
        ):
            payload = self.staging_manifest()
            payload[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(CampaignManifestError):
                    load_staging_campaign(self.write_manifest(payload))

    def test_offline_campaign_is_not_a_staging_campaign(self) -> None:
        with self.assertRaises(CampaignManifestError):
            load_staging_campaign(self.write_manifest(self.manifest()))


class StagingGarakRunnerTests(StagingCampaignTests):
    def make_config(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        config = Path(directory.name) / "garak.json"
        config.write_text("{}", encoding="utf-8")
        return config

    def test_invokes_garak_with_committed_config_and_fixed_spec(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def process_runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
            calls.append((argv, kwargs))
            prefix = Path(argv[argv.index("--report_prefix") + 1])
            prefix.with_suffix(".report.jsonl").write_text(
                '{"entry_type":"eval","total_evaluated":1,"fails":0}\n{"entry_type":"completion"}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(argv, 0)

        config = self.make_config()
        result = StagingGarakRunner(
            Path("/reviewed/bin/garak"), config, process_runner,
            campaign_loader=load_staging_campaign,
        ).run(
            self.write_manifest(self.staging_manifest())
        )

        self.assertEqual(result.status, GarakRunStatus.COMPLETED)
        self.assertEqual(result.summary.attempt_count, 1)
        argv, kwargs = calls[0]
        self.assertEqual(
            argv[:7],
            [
                "/reviewed/bin/garak",
                "--config",
                str(config),
                "--target_type",
                "rest.RestGenerator",
                "--spec",
                "encoding.InjectBase64",
            ],
        )
        self.assertEqual(kwargs["env"]["HTTP_PROXY"], "")
        self.assertEqual(kwargs["env"]["NO_PROXY"], "*")

    def test_revalidates_an_unapproved_manifest_without_invoking(self) -> None:
        payload = self.staging_manifest()
        payload["target"]["host"] = "example.com"
        invoked = False

        def process_runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[object]:
            nonlocal invoked
            invoked = True
            return subprocess.CompletedProcess([], 0)

        config = self.make_config()
        result = StagingGarakRunner(
            Path("/reviewed/bin/garak"), config, process_runner,
            campaign_loader=load_staging_campaign,
        ).run(
            self.write_manifest(payload)
        )

        self.assertEqual(result.status, GarakRunStatus.INCOMPLETE)
        self.assertEqual(result.error, GarakRunError.INVALID_REPORT)
        self.assertFalse(invoked)

    def test_missing_executable_timeout_and_bad_exit_are_incomplete(self) -> None:
        cases = (
            (FileNotFoundError(), GarakRunError.EXECUTABLE_UNAVAILABLE),
            (subprocess.TimeoutExpired(["garak"], 90), GarakRunError.TIMEOUT),
            (subprocess.CompletedProcess([], 2), GarakRunError.BAD_EXIT),
        )
        config = self.make_config()
        for outcome, error in cases:
            def process_runner(*_args: object, outcome: object = outcome, **_kwargs: object) -> object:
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

            with self.subTest(error=error):
                result = StagingGarakRunner(
                    Path("/reviewed/bin/garak"), config, process_runner,
                    campaign_loader=load_staging_campaign,
                ).run(
                    self.write_manifest(self.staging_manifest())
                )
                self.assertEqual(result.status, GarakRunStatus.INCOMPLETE)
                self.assertEqual(result.error, error)

    def test_requires_absolute_executable_and_existing_config(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute"):
            StagingGarakRunner(Path("garak"), Path("/reviewed/config/garak.json"))
        with self.assertRaisesRegex(ValueError, "config"):
            StagingGarakRunner(Path("/reviewed/bin/garak"), Path("/missing/config.json"))

    def test_default_runner_rejects_a_noncanonical_manifest_without_invoking(self) -> None:
        invoked = False

        def process_runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[object]:
            nonlocal invoked
            invoked = True
            return subprocess.CompletedProcess([], 0)

        result = StagingGarakRunner(
            Path("/reviewed/bin/garak"), self.make_config(), process_runner
        ).run(self.write_manifest(self.staging_manifest()))

        self.assertEqual(result.status, GarakRunStatus.INCOMPLETE)
        self.assertEqual(result.error, GarakRunError.INVALID_REPORT)
        self.assertFalse(invoked)
