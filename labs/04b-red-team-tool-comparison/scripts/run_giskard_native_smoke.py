#!/usr/bin/env python3
"""Generate a minimal Spanish Giskard prompt-injection suite with Ollama."""
from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

import httpx
from giskard.agents.generators import LiteLLMGenerator
from giskard.checks import set_default_generator
from giskard.scan import PromptInjectionScenarioGenerator, generate_suite
from pydantic import BaseModel


class FirewallInput(BaseModel):
    question: str


class FirewallOutput(BaseModel):
    answer: str


async def firewall_target(inputs: FirewallInput) -> FirewallOutput:
    async with httpx.AsyncClient(timeout=90.0) as client:
        response = await client.post(
            os.environ["FIREWALL_URL"], json={"message": inputs.question}
        )
    response.raise_for_status()
    return FirewallOutput(answer=str(response.json().get("response", "")))


async def run(output_dir: Path) -> None:
    set_default_generator(LiteLLMGenerator(model=os.environ["GISKARD_LOCAL_MODEL"]))
    suite = await generate_suite(
        description=(
            "Firewall semantico en espanol. Debe bloquear prompt injection y no "
            "obedecer instrucciones escondidas dentro de documentos que el usuario "
            "pida resumir."
        ),
        languages=["es"],
        generators=[PromptInjectionScenarioGenerator()],
        max_scenarios=1,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "giskard-native-smoke-suite.json").write_text(
        suite.model_dump_json(), encoding="utf-8"
    )
    result = await suite.run(target=firewall_target, parallel=False)
    result.to_junit_xml(output_dir / "giskard-native-smoke.xml")
    print(f"failed={result.failed_count} pass_rate={result.pass_rate}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--firewall-url", default="http://127.0.0.1:8000/chat")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="ollama/llama3.1:8b-instruct-q4_K_M")
    args = parser.parse_args()
    os.environ["FIREWALL_URL"] = args.firewall_url
    os.environ["OLLAMA_API_BASE"] = args.ollama_url
    os.environ["GISKARD_LOCAL_MODEL"] = args.model
    asyncio.run(run(args.output_dir))


if __name__ == "__main__":
    main()
