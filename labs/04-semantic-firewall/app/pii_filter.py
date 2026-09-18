"""Layers 2 and 4: Presidio PII detection and anonymization.

The filter supports English and Spanish input and output. It uses a low score
threshold to retain phone-number detections, excludes known noisy entity types,
and ignores selected greetings. A ``PERSON`` entity followed by a colon is
treated as a field label rather than a name, avoiding false positives such as
``Phone:`` in generated templates.
"""
import re
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

SCORE_THRESHOLD = 0.3
PERSON_STOPWORDS = {"hola", "adios", "adiós", "gracias", "buenos dias", "buenos días"}
EXCLUDED_ENTITY_TYPES = {"LOCATION", "URL"}


def _build_nlp_config():
    return {
        "nlp_engine_name": "spacy",
        "models": [
            {"lang_code": "en", "model_name": "en_core_web_lg"},
            {"lang_code": "es", "model_name": "es_core_news_lg"},
        ],
    }


_analyzer = None
_anonymizer = None


def get_engines():
    """Create the heavyweight NLP engines once per process."""
    global _analyzer, _anonymizer
    if _analyzer is None:
        provider = NlpEngineProvider(nlp_configuration=_build_nlp_config())
        nlp_engine = provider.create_engine()
        _analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en", "es"])
        _anonymizer = AnonymizerEngine()
    return _analyzer, _anonymizer


def _is_field_label(text: str, entity_start: int, entity_end: int) -> bool:
    """Return whether the entity is followed by a colon-style field label."""
    remainder = text[entity_end:entity_end + 3]
    return bool(re.match(r"\s*:", remainder))


def anonymize(text: str, language: str = "es") -> dict:
    """Return redacted text and minimal detection metadata."""
    analyzer, anonymizer = get_engines()

    raw_results = analyzer.analyze(text=text, language=language, score_threshold=SCORE_THRESHOLD)

    results = [
        r for r in raw_results
        if r.entity_type not in EXCLUDED_ENTITY_TYPES
        and not (r.entity_type == "PERSON" and text[r.start:r.end].strip().lower() in PERSON_STOPWORDS)
        and not (r.entity_type == "PERSON" and _is_field_label(text, r.start, r.end))
    ]

    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)

    return {
        "anonymized_text": anonymized.text,
        "entities_found": [r.entity_type for r in results],
        "had_pii": len(results) > 0,
    }


if __name__ == "__main__":
    tests = [
        "Hello, I am Demo User and my email is demo.user@example.test",
        "What is the capital of France?",
        "My card is 4111 1111 1111 1111 and my phone is +34 611 222 333",
        "- Email: [YOUR EMAIL]\n- Phone: [YOUR PHONE] (if you wish to provide it)",
    ]
    for t in tests:
        result = anonymize(t)
        print(f"'{t[:60]}...' -> {result}")
