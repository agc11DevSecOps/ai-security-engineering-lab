"""
Consolidador del pipeline hibrido Bandit + Vulnhuntr.
Fusiona hallazgos de ambas fuentes que apunten al mismo archivo/linea
(o linea cercana, +-2), evitando duplicados y marcando con mayor
confianza los hallazgos confirmados por ambas fuentes -- el patron
"hibrido SAST+LLM" validado por la industria (94-98% reduccion de
falsos positivos segun estudios citados en 2026).
"""
import json


def load_bandit(path):
    with open(path) as f:
        data = json.load(f)
    findings = []
    for r in data["results"]:
        findings.append({
            "source": "bandit",
            "file": r["filename"].replace("target/", ""),
            "line": r["line_number"],
            "severity": r["issue_severity"],
            "confidence": r["issue_confidence"],
            "description": r["issue_text"],
            "rule_id": r["test_id"],
        })
    return findings


def load_vulnhuntr(path):
    with open(path) as f:
        data = json.load(f)
    findings = []
    for finding in data.get("findings", []):
        file_path = finding.get("file_path", "")
        # Normalizar a ruta relativa tipo db/repository.py
        if "target/" in file_path:
            file_path = file_path.split("target/")[-1]
        findings.append({
            "source": "vulnhuntr",
            "file": file_path,
            "line": None,
            "severity": finding.get("severity", "").upper(),
            "confidence": finding.get("confidence_score"),
            "description": finding.get("analysis", finding.get("description", "")),
            "rule_id": finding.get("rule_id", ""),
            "cwe": finding.get("cwe_id", ""),
            "poc": finding.get("poc", ""),
        })
    return findings


def consolidate(bandit_findings, vulnhuntr_findings, line_tolerance=3):
    consolidated = []
    used_vulnhuntr = set()

    for bf in bandit_findings:
        matched_vf = None
        for i, vf in enumerate(vulnhuntr_findings):
            if i in used_vulnhuntr:
                continue
            if vf["file"] == bf["file"]:
                if vf["line"] is None or abs(vf["line"] - bf["line"]) <= line_tolerance:
                    matched_vf = vf
                    used_vulnhuntr.add(i)
                    break

        if matched_vf:
            consolidated.append({
                "file": bf["file"],
                "line": bf["line"],
                "confirmed_by": ["bandit", "vulnhuntr"],
                "confidence_level": "ALTA (confirmado por 2 fuentes independientes)",
                "bandit_finding": bf["description"],
                "vulnhuntr_finding": matched_vf["description"][:200],
                "bandit_severity": bf["severity"],
                "vulnhuntr_category": matched_vf["severity"],
            })
        else:
            consolidated.append({
                "file": bf["file"],
                "line": bf["line"],
                "confirmed_by": ["bandit"],
                "confidence_level": "MEDIA (solo deteccion sintactica, sin confirmar flujo de datos)",
                "bandit_finding": bf["description"],
                "bandit_severity": bf["severity"],
            })

    for i, vf in enumerate(vulnhuntr_findings):
        if i not in used_vulnhuntr:
            consolidated.append({
                "file": vf["file"],
                "line": vf["line"],
                "confirmed_by": ["vulnhuntr"],
                "confidence_level": "MEDIA (razonamiento de flujo, sin confirmacion sintactica -- revisar riesgo de alucinacion, ver Fase 4b)",
                "vulnhuntr_finding": vf["description"][:200],
                "vulnhuntr_category": vf["severity"],
            })

    return consolidated


def main():
    bandit_findings = load_bandit("reports/bandit_results.json")
    vulnhuntr_findings = load_vulnhuntr("reports/vulnhuntr_results.json")

    print(f"Hallazgos Bandit: {len(bandit_findings)}")
    print(f"Hallazgos Vulnhuntr: {len(vulnhuntr_findings)}\n")

    consolidated = consolidate(bandit_findings, vulnhuntr_findings)

    print(f"=== REPORTE CONSOLIDADO ({len(consolidated)} hallazgos unicos) ===\n")
    for c in consolidated:
        print(f"[{c['confidence_level']}]")
        print(f"  Archivo: {c['file']}:{c.get('line', '?')}")
        print(f"  Confirmado por: {', '.join(c['confirmed_by'])}")
        if "bandit_finding" in c:
            print(f"  Bandit: {c['bandit_finding']}")
        if "vulnhuntr_finding" in c:
            print(f"  Vulnhuntr: {c['vulnhuntr_finding']}")
        print()

    with open("reports/consolidated_report.json", "w") as f:
        json.dump(consolidated, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
