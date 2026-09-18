"""Send a reviewed structured triage summary to an approved Slack webhook.

This script does not validate triage quality. Call it only after deterministic
validation and human review, and never include sensitive findings in a channel
that has not been approved for the data classification.
"""
import os
import sys
import json
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


def load_triage(path):
    with open(path) as f:
        return json.load(f)["triage"]


def build_message(triage_items, model_name):
    bloqueantes = [i for i in triage_items if i.get("category") == "BLOQUEANTE"]
    deuda = [i for i in triage_items if i.get("category") == "DEUDA_TECNICA"]

    lines = [f"*Automated advisory triage ({model_name})*"]
    lines.append(f"{len(bloqueantes)} blocking item(s), {len(deuda)} technical-debt item(s)\n")

    if bloqueantes:
        lines.append("*BLOQUEANTE (requires review before merge):*")
        for item in sorted(bloqueantes, key=lambda x: x.get("priority_rank", 99)):
            lines.append(f"  - `{item['test_id']}`: {item['reasoning']}")

    if deuda:
        lines.append("\n*Technical debt (non-blocking, track for remediation):*")
        for item in sorted(deuda, key=lambda x: x.get("priority_rank", 99)):
            lines.append(f"  - `{item['test_id']}`: {item['reasoning'][:100]}...")

    return "\n".join(lines)


def send_slack_message(text):
    if not WEBHOOK_URL:
        raise RuntimeError("SLACK_WEBHOOK_URL is not configured in .env")
    parsed_url = urlparse(WEBHOOK_URL)
    if parsed_url.scheme != "https" or parsed_url.netloc != "hooks.slack.com":
        raise RuntimeError("SLACK_WEBHOOK_URL must use the approved HTTPS Slack webhook host")
    response = requests.post(WEBHOOK_URL, json={"text": text}, timeout=15)
    response.raise_for_status()
    return response


def main():
    triage_path = sys.argv[1] if len(sys.argv) > 1 else "sample_findings/triage_llama3_1_8b-instruct-q4_K_M.json"
    model_name = sys.argv[2] if len(sys.argv) > 2 else "llama3.1:8b"

    triage_items = load_triage(triage_path)
    message = build_message(triage_items, model_name)

    print("=== Message to be sent ===")
    print(message)
    print("===================================\n")

    send_slack_message(message)
    print("Message sent to Slack.")


if __name__ == "__main__":
    main()
