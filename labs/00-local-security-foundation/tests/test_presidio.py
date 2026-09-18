"""Demonstrate local PII detection and anonymization with synthetic text."""

from pathlib import Path
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

CONFIG_PATH = Path(__file__).parent / "nlp_config.yaml"

SAMPLE_TEXT = (
    "Hello, I am Example Person. My email is person@example.invalid "
    "and my demonstration card number is 4111 1111 1111 1111. Call me at +1 202 555 0147."
)

# Keep this threshold low to remove only extreme noise. Raising it globally can
# suppress phone-number detections because recognizers use different score scales.
SCORE_THRESHOLD = 0.3

# Known recurring Spanish NER false positives for PERSON. Extend this targeted
# allowlist after approved evaluation instead of changing the global threshold.
PERSON_STOPWORDS = {"hola", "adios", "adiós", "gracias", "buenos dias", "buenos días"}

def main():
    provider = NlpEngineProvider(conf_file=str(CONFIG_PATH))
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en", "es"])
    anonymizer = AnonymizerEngine()

    print(f"Original text:\n{SAMPLE_TEXT}\n")
    raw_results = analyzer.analyze(text=SAMPLE_TEXT, language="es", score_threshold=SCORE_THRESHOLD)

    results = [
        r for r in raw_results
        if not (r.entity_type == "PERSON" and SAMPLE_TEXT[r.start:r.end].strip().lower() in PERSON_STOPWORDS)
    ]

    print("Detected entities:")
    for r in results:
        entity_text = SAMPLE_TEXT[r.start:r.end]
        print(f"  - {r.entity_type}: '{entity_text}' (score={r.score:.2f})")

    anonymized = anonymizer.anonymize(text=SAMPLE_TEXT, analyzer_results=results)
    print(f"\nAnonymized text:\n{anonymized.text}")

if __name__ == "__main__":
    main()
