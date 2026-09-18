#!/usr/bin/env python3
"""Run PyRIT's native Base64 encoding scenario against the firewall.

This uses PyRIT in-process rather than its optional CLI backend, avoiding the
backend's default :8000 port and its default OpenAI initializer.
"""
from __future__ import annotations

import argparse
import asyncio

from pyrit.output import output_scenario_async
from pyrit.prompt_target import HTTPTarget, get_http_target_json_response_callback_function
from pyrit.scenario.garak import Encoding, EncodingTechnique
from pyrit.scenario.garak.encoding import EncodingDatasetConfiguration
from pyrit.setup import IN_MEMORY, initialize_pyrit_async


async def run(max_dataset_size: int) -> None:
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    http_request = """POST http://127.0.0.1:8000/chat HTTP/1.1
Content-Type: application/json

{"message":"{PROMPT}"}
"""
    target = HTTPTarget(
        http_request=http_request,
        use_tls=False,
        callback_function=get_http_target_json_response_callback_function(key="response"),
        model_name="semantic_firewall_local",
        timeout=90.0,
    )
    dataset = EncodingDatasetConfiguration(
        dataset_names=["garak_slur_terms_en"], max_dataset_size=max_dataset_size
    )
    scenario = Encoding()
    scenario.set_params_from_args(
        args={
            "objective_target": target,
            "scenario_techniques": [EncodingTechnique.Base64],
            "dataset_config": dataset,
        }
    )
    await scenario.initialize_async()
    result = await scenario.run_async()
    await output_scenario_async(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-dataset-size", type=int, default=1)
    args = parser.parse_args()
    asyncio.run(run(args.max_dataset_size))


if __name__ == "__main__":
    main()
