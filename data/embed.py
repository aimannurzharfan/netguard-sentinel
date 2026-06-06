"""Generate sentence embeddings for CVE descriptions.

Uses sentence-transformers locally (all-MiniLM-L6-v2, 384 dimensions).
Chosen over Oracle in-DB ONNX because it avoids uploading an ONNX model
artifact to the container and keeps the embedding step runnable on any machine
without extra Oracle configuration. The model is small (~22 MB) and fast.
"""

from __future__ import annotations

from functools import lru_cache

from sentence_transformers import SentenceTransformer

MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384


@lru_cache(maxsize=1)
def _model() -> SentenceTransformer:
    return SentenceTransformer(MODEL_NAME)


def embed(text: str) -> list[float]:
    """Return a 384-dimensional embedding for text."""
    vec = _model().encode(text, normalize_embeddings=True)
    return vec.tolist()


def embed_batch(texts: list[str]) -> list[list[float]]:
    """Return embeddings for a list of texts (more efficient than calling embed() in a loop)."""
    vecs = _model().encode(texts, normalize_embeddings=True, batch_size=32)
    return [v.tolist() for v in vecs]
