"""Regression test for the CPU loading configuration of Prompt Guard."""
import unittest
from unittest.mock import patch

from app import prompt_guard


class PromptGuardTests(unittest.TestCase):
    def test_cpu_loading_disables_meta_device_initialization(self):
        prompt_guard._classifier = None
        with patch("app.prompt_guard.pipeline", return_value=object()) as mocked_pipeline:
            prompt_guard.get_classifier()

        self.assertEqual(mocked_pipeline.call_args.kwargs["device"], -1)
        self.assertEqual(
            mocked_pipeline.call_args.kwargs["model_kwargs"],
            {"low_cpu_mem_usage": False},
        )
        prompt_guard._classifier = None


if __name__ == "__main__":
    unittest.main()
