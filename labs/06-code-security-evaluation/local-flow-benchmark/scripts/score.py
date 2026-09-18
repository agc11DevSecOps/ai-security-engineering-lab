#!/usr/bin/env python3
"""Normaliza resultados de scanners y calcula metricas contra el ground truth."""
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FLOW_PATHS = {"routes/api.py", "services/report_service.py", "db/repository.py"}


def _contains_sqli(value: object) -> bool:
    """Keep the SQLi-only matcher used by the separate local LLM triage flow."""
    text = json.dumps(value, ensure_ascii=False).lower()
    return any(marker in text for marker in ("sql injection", "sql-injection", "cwe-89", "cwe-089"))


def _contains_relevant_security_finding(value: object) -> bool:
    text = json.dumps(value, ensure_ascii=False).lower()
    return any(
        marker in text
        for marker in (
            "sql injection",
            "sql-injection",
            "cwe-89",
            "cwe-089",
            "command injection",
            "command-line injection",
            "os command injection",
            "cwe-78",
            "cwe-078",
            "path traversal",
            "path-injection",
            "path injection",
            "cwe-22",
            "cwe-022",
            "insecure deserialization",
            "unsafe deserialization",
            "deserialization of untrusted data",
            "cwe-502",
            "cross-site scripting",
            "cross site scripting",
            "cwe-79",
            "code injection",
            "cwe-94",
            "server-side request forgery",
            "server side request forgery",
            "ssrf",
            "cwe-918",
        )
    )


def _codeql_flow_paths(result: dict) -> set[str]:
    paths = set()
    for code_flow in result.get("codeFlows", []):
        for thread_flow in code_flow.get("threadFlows", []):
            for location in thread_flow.get("locations", []):
                uri = location.get("location", {}).get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                for expected in FLOW_PATHS:
                    if uri.endswith(expected):
                        paths.add(expected)
    return paths


def _location(path: object, line: object) -> dict[str, object] | None:
    if not isinstance(path, str) or not isinstance(line, int) or line < 1:
        return None
    for expected in FLOW_PATHS:
        if path.endswith(expected):
            return {"path": expected, "line": line}
    return None


def parse_bandit(path: Path) -> dict:
    data = json.loads(path.read_text())
    results = data.get("results", [])
    relevant = [result for result in results if result.get("test_id") in {"B301", "B307", "B602", "B608"} or _contains_relevant_security_finding(result)]
    locations = [
        location
        for result in relevant
        if (location := _location(result.get("filename"), result.get("line_number")))
        is not None
    ]
    return {"raw_count": len(results), "relevant_count": len(relevant), "detected": bool(relevant), "flow_paths": [], "locations": locations}


def parse_semgrep(path: Path) -> dict:
    data = json.loads(path.read_text())
    results = data.get("results", [])
    relevant = [
        result
        for result in results
        if result.get("check_id") in {"f4f.sqlite-string-concat-execute", "f4f.subprocess-shell-true", "f4f.path-join-untrusted", "f4f.pickle-loads-untrusted", "f4f.html-response-untrusted", "f4f.eval-untrusted", "f4f.requests-untrusted-url"}
        or _contains_relevant_security_finding(result)
    ]
    locations = [
        location
        for result in relevant
        if (location := _location(result.get("path"), result.get("start", {}).get("line")))
        is not None
    ]
    return {"raw_count": len(results), "relevant_count": len(relevant), "detected": bool(relevant), "flow_paths": [], "locations": locations}


def parse_codeql(path: Path) -> dict:
    data = json.loads(path.read_text())
    results = [result for run in data.get("runs", []) for result in run.get("results", [])]
    relevant = [result for result in results if _contains_relevant_security_finding(result)]
    flow_paths = set()
    locations = []
    for result in relevant:
        flow_paths.update(_codeql_flow_paths(result))
        physical = result.get("locations", [{}])[0].get("physicalLocation", {})
        location = _location(
            physical.get("artifactLocation", {}).get("uri"),
            physical.get("region", {}).get("startLine"),
        )
        if location is not None:
            locations.append(location)
    return {
        "raw_count": len(results),
        "relevant_count": len(relevant),
        "detected": bool(relevant),
        "flow_paths": sorted(flow_paths),
        "locations": locations,
    }


def _is_vulnerable(case: dict) -> bool:
    if "verdict" in case:
        return case["verdict"] == "vulnerable"
    return bool(case["expected_findings"])


def _matched_expected_location(result: dict, case: dict) -> bool:
    accepted = [
        (location["path"], location["line"])
        for finding in case.get("expected_findings", [])
        for location in finding.get("accepted_detection_locations", [])
    ]
    if not accepted or "locations" not in result:
        return result["detected"]
    return any(
        (location.get("path"), location.get("line")) in accepted
        for location in result["locations"]
    )


def score_observations(observations: list[dict], ground_truth: dict) -> dict:
    by_tool: dict[str, dict] = {}
    for observation in observations:
        tool = observation["tool"]
        case = observation["case"]
        expected_vulnerable = _is_vulnerable(ground_truth["cases"][case])
        score = by_tool.setdefault(tool, {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "unavailable": 0, "flow_evidence": 0})

        if observation["status"] != "success":
            score["unavailable"] += 1
            continue

        detected = observation["result"]["detected"]
        matched = _matched_expected_location(observation["result"], ground_truth["cases"][case])
        if expected_vulnerable and detected and matched:
            score["tp"] += 1
            if set(observation["result"].get("flow_paths", [])) == FLOW_PATHS:
                score["flow_evidence"] += 1
        elif expected_vulnerable:
            score["fn"] += 1
        elif detected:
            score["fp"] += 1
        else:
            score["tn"] += 1

    for score in by_tool.values():
        tp, fp, fn = score["tp"], score["fp"], score["fn"]
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        score["precision"] = precision
        score["recall"] = recall
        score["f1"] = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None

    return by_tool


def main() -> None:
    raw_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "reports" / "raw_results.json"
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "reports" / "scorecard.json"
    raw = json.loads(raw_path.read_text())
    ground_truth = json.loads((ROOT / "ground_truth.json").read_text())
    scorecard = score_observations(raw["observations"], ground_truth)
    output_path.write_text(json.dumps(scorecard, indent=2) + "\n")
    print(json.dumps(scorecard, indent=2))


if __name__ == "__main__":
    main()
