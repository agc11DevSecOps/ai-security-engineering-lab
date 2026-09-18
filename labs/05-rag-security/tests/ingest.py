"""Ingest the complete synthetic corpus into Qdrant.

Benign and adversarial documents share one collection to model retrieval
poisoning under controlled lab conditions.
"""
import os
import glob
import requests
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

OLLAMA_HOST = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "rag_corpus"
CORPUS_DIRS = ["corpus", "malicious_docs"]


def get_embedding(text):
    response = requests.post(
        f"{OLLAMA_HOST}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["embedding"]


def main():
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    sample_embedding = get_embedding("texto de prueba")
    dim = len(sample_embedding)
    print(f"Dimension del embedding: {dim}")

    if client.collection_exists(COLLECTION_NAME):
        client.delete_collection(COLLECTION_NAME)
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
    )

    files = []
    for d in CORPUS_DIRS:
        files.extend(sorted(glob.glob(f"{d}/*.txt")))
    print(f"Documentos encontrados: {len(files)}")

    points = []
    for i, filepath in enumerate(files):
        with open(filepath) as f:
            text = f.read()
        embedding = get_embedding(text)
        is_malicious = "malicious_docs" in filepath
        points.append(
            PointStruct(
                id=i,
                vector=embedding,
                payload={
                    "filename": os.path.basename(filepath),
                    "text": text,
                    "source": "malicious" if is_malicious else "legitimate",
                },
            )
        )
        tag = "[MALICIOSO]" if is_malicious else "[legitimo]"
        print(f"  {tag} Ingestado: {os.path.basename(filepath)}")

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"\n{len(points)} documentos ingestados en la coleccion '{COLLECTION_NAME}'")


if __name__ == "__main__":
    main()
