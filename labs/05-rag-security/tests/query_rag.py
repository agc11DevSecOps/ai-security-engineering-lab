"""Embed a query, retrieve relevant Qdrant documents, and send context to the LLM."""
import sys
import requests
from qdrant_client import QdrantClient

OLLAMA_HOST = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "llama3.1:8b-instruct-q4_K_M"
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "rag_corpus"
TOP_K = 2


def get_embedding(text):
    response = requests.post(
        f"{OLLAMA_HOST}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["embedding"]


def retrieve(client, query, top_k=TOP_K):
    query_embedding = get_embedding(query)
    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_embedding,
        limit=top_k,
    ).points
    return results


def generate_answer(query, retrieved_docs):
    context = "\n\n".join(
        f"[Documento: {r.payload['filename']}]\n{r.payload['text']}" for r in retrieved_docs
    )
    prompt = f"""Responde a la pregunta del usuario basandote UNICAMENTE en el siguiente contexto recuperado.

CONTEXTO:
{context}

PREGUNTA: {query}

Responde de forma breve y precisa, citando de que documento sacas la informacion."""

    response = requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json={"model": LLM_MODEL, "prompt": prompt, "stream": False},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()["response"]


def main():
    query = sys.argv[1] if len(sys.argv) > 1 else "Que es Python?"
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    print(f"Consulta: {query}\n")
    retrieved = retrieve(client, query)

    print("=== Documentos recuperados ===")
    for r in retrieved:
        print(f"  [{r.score:.4f}] {r.payload['filename']}")
    print()

    answer = generate_answer(query, retrieved)
    print("=== Respuesta del LLM ===")
    print(answer)


if __name__ == "__main__":
    main()
