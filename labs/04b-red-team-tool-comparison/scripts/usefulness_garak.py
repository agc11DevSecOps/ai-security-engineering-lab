"""Garak 0.16 native probes, harness, detectors and report/hitlog writers."""
from pathlib import Path
import json
import random

from evaluate_tool_usefulness import write_json


def run(args, target):
    import datetime
    from garak import _config, _plugins, command, payloads
    from garak.attempt import Message
    from garak.generators.base import Generator
    from garak.harnesses import base as harness_base
    from garak.harnesses.base import Harness
    from garak.evaluators.base import ThresholdEvaluator

    class BoundedGenerator(Generator):
        """Native generator adapter; the shared transport enforces the hard budget."""
        name = "bounded-controlled-target"
        generator_family_name = "Usefulness"

        def _call_model(self, prompt, generations_this_call=1):
            if generations_this_call != 1:
                raise ValueError("Only one generation is permitted")
            return [Message(target.call(prompt.last_message().text))]

    _original_emit = harness_base._emit_plugin_cache_entry

    def _tolerant_emit(*plugin_instances):
        # Custom controlled generator is intentionally not a garak plugin;
        # keep native probes/detectors in the cache without failing the run.
        recognised = []
        for instance in plugin_instances:
            if instance is None:
                continue
            classpath = (
                f"{instance.__class__.__module__}.{instance.__class__.__name__}"
            ).replace("garak.", "")
            if classpath.split(".")[0] not in _plugins.PLUGIN_TYPES:
                continue
            recognised.append(instance)
        return _original_emit(*recognised)

    harness_base._emit_plugin_cache_entry = _tolerant_emit
    Harness.run.__globals__["_emit_plugin_cache_entry"] = _tolerant_emit
    if getattr(_config.transient, "starttime", None) is None:
        _config.transient.starttime = datetime.datetime.now()
        _config.transient.starttime_iso = _config.transient.starttime.isoformat()
    _config.load_config(site_config_filename="usefulness-no-site-config.yaml")
    _config.system.lite = False
    _config.system.parallel_requests = 1
    _config.system.parallel_attempts = 1
    _config.system.show_z = False
    _config.run.generations = 1
    _config.reporting.report_dir = str(args.output_dir)
    _config.reporting.report_prefix = "garak"
    _config.reporting.confidence_interval_method = "wilson"
    random.seed(0)
    # 0.16 has no public additional-payload-path parameter. Register an actual
    # on-disk PayloadGroup in its Director; native probes still generate prompts.
    fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/usefulness_payload.json"
    payloads.Director()
    payloads.Director.payload_list["usefulness_payload"] = {"path": fixture, "types": ["Text"]}
    _config.plugins.probes["encoding"] = {"payloads": ["usefulness_payload"],
                                         "soft_probe_prompt_cap": args.per_probe}
    names = ["encoding.InjectBase64", "encoding.InjectROT13", "encoding.InjectHex", "dan.Dan_11_0"]
    command.start_run()
    try:
        harness = Harness()
        model = BoundedGenerator()
        evaluator = ThresholdEvaluator(0.5)
        manifest = []
        for name in names:
            probe = _plugins.load_plugin("probes." + name)
            # Slice aligned encoding metadata together; no native prompt rewriting.
            for field in ("prompts", "triggers", "_prompt_intents"):
                if hasattr(probe, field):
                    setattr(probe, field, getattr(probe, field)[:args.per_probe])
            if not probe.prompts:
                raise RuntimeError(f"No native prompts loaded for {name}")
            detector = _plugins.load_plugin("detectors." + probe.primary_detector)
            manifest.append({"probe": name, "detector": probe.primary_detector,
                             "prompts": list(probe.prompts)})
            harness.run(model, [probe], [detector], evaluator)
        write_json(args.output_dir / "probe-manifest.json", manifest)
    finally:
        command.end_run()
    rows = [json.loads(line) for line in (args.output_dir / "garak.report.jsonl").read_text().splitlines()]
    attempts = [row for row in rows if row.get("entry_type") == "attempt" and row.get("status") == 2]
    if len(attempts) != len(target.records):
        raise RuntimeError("Native completed-attempt count differs from target call count")
    return {"execution": "Native Probe.probe via Harness.run; native primary detectors and evaluator",
            "probes": names, "native_completed_attempts": len(attempts),
            "native_evaluations": [row for row in rows if row.get("entry_type") == "eval"],
            "native_artifacts": [p.name for p in args.output_dir.glob("garak.*")],
            "limitations": ["Bounded canary encoding and DAN coverage, not the entire Garak catalog.",
                            "DAN detector hits indicate a marker, not proof of harmful compliance."]}
