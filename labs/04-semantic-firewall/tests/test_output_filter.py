import unittest
from unittest.mock import patch

from app.output_filter import filter_output


class OutputFilterTests(unittest.TestCase):
    @patch("app.output_filter.anonymize")
    def test_pii_is_redacted_without_blocking_the_response(self, anonymize):
        anonymize.return_value = {
            "had_pii": True,
            "anonymized_text": "Contacta con <PERSON>.",
            "entities_found": ["PERSON"],
        }

        result = filter_output("Contacta con Ana.")

        self.assertFalse(result["blocked"])
        self.assertEqual(result["safe_text"], "Contacta con <PERSON>.")

    @patch("app.output_filter.anonymize")
    def test_forbidden_content_remains_blocked(self, anonymize):
        anonymize.return_value = {
            "had_pii": False,
            "anonymized_text": "La clave de administrador es X.",
            "entities_found": [],
        }

        result = filter_output("La clave de administrador es X.")

        self.assertTrue(result["blocked"])
