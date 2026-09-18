"""Layer 3: call a fixed local Ollama endpoint.

The caller supplies text that the input PII filter has already anonymized. The
endpoint and model are fixed so chat input cannot become an arbitrary network
request or model-selection instruction.
"""
import requests

OLLAMA_HOST = "http://localhost:11434"
MODEL = "llama3.1:8b-instruct-q4_K_M"


def query_llm(prompt: str, timeout: int = 60) -> str:
    """Return a non-empty text response from the configured local model."""
    response = requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    text = payload.get("response")
    if not isinstance(text, str) or not text:
        raise ValueError("local model response did not include non-empty text")
    return text


if __name__ == "__main__":
    result = query_llm("Answer in one sentence: what is a semantic firewall?")
    print(result)
