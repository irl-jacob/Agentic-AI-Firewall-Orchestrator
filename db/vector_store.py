"""Enhanced Vector store for firewall documentation retrieval.

Uses Ollama embeddings with a local JSON-based store.
Implements hybrid search (BM25 + embeddings) with metadata filtering.
Falls back to keyword-based retrieval when Ollama is unavailable.
"""

import json
import math
import os
import re
from collections import Counter
from pathlib import Path

import httpx
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

DOCS_DIR = Path(__file__).parent.parent / "docs"
STORE_DIR = Path(__file__).parent.parent / ".vectorstore"
STORE_FILE = STORE_DIR / "embeddings.json"

def _get_ollama_host() -> str:
    return os.environ.get("OLLAMA_HOST", "http://localhost:11434")

def _get_embed_model() -> str:
    return os.environ.get("EMBED_MODEL", "nomic-embed-text")

# Chunking parameters - increased for better context
CHUNK_SIZE = 1500
CHUNK_OVERLAP = 200

# BM25 parameters
K1 = 1.5  # Term frequency saturation parameter
B = 0.75  # Length normalization parameter


def _ollama_reachable() -> bool:
    """Check if Ollama is reachable."""
    try:
        resp = httpx.get(f"{_get_ollama_host()}/api/tags", timeout=3)
        return resp.status_code == 200
    except (httpx.ConnectError, httpx.TimeoutException):
        return False


def _embed(texts: list[str]) -> list[list[float]]:
    """Get embeddings from Ollama."""
    url = f"{_get_ollama_host()}/api/embed"
    resp = httpx.post(url, json={"model": _get_embed_model(), "input": texts}, timeout=60.0)
    resp.raise_for_status()
    return resp.json()["embeddings"]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _get_doc_metadata(filename: str) -> dict:
    """Extract metadata from document filename and content."""
    filename_lower = filename.lower()

    # Determine backend type
    if "nftables" in filename_lower:
        backend = "nftables"
        category = "linux"
    elif "iptables" in filename_lower:
        backend = "iptables"
        category = "linux"
    elif "opnsense" in filename_lower:
        backend = "opnsense"
        category = "bsd"
    elif "aws" in filename_lower or "security_group" in filename_lower:
        backend = "aws"
        category = "cloud"
    else:
        backend = "general"
        category = "general"

    # Determine document type based on content structure
    doc_type = "reference"

    return {
        "backend": backend,
        "category": category,
        "doc_type": doc_type,
        "filename": filename,
    }


def _load_and_chunk_docs() -> list[dict]:
    """Load markdown docs and split into chunks with metadata."""
    chunks = []

    header_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=[
            ("#", "h1"),
            ("##", "h2"),
            ("###", "h3"),
            ("####", "h4"),
        ]
    )

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n## ", "\n### ", "\n#### ", "\n\n", "\n", "```", ". ", " "],
        length_function=len,
    )

    for md_file in sorted(DOCS_DIR.glob("*.md")):
        content = md_file.read_text()
        doc_metadata = _get_doc_metadata(md_file.name)

        try:
            header_docs = header_splitter.split_text(content)
        except Exception:
            # If header splitting fails, treat entire doc as one
            # Create a simple container class
            class DocChunk:
                def __init__(self, page_content, metadata):
                    self.page_content = page_content
                    self.metadata = metadata
            header_docs = [DocChunk(page_content=content, metadata={})]

        for doc in header_docs:
            # Build section hierarchy
            section_parts = []
            for h in ["h1", "h2", "h3", "h4"]:
                if doc.metadata.get(h):
                    section_parts.append(doc.metadata[h])
            section = " > ".join(section_parts) if section_parts else ""

            sub_chunks = text_splitter.split_text(doc.page_content)
            for i, chunk_text in enumerate(sub_chunks):
                chunks.append({
                    "text": chunk_text,
                    "metadata": {
                        **doc_metadata,
                        "source": md_file.name,
                        "section": section,
                        "chunk_index": i,
                        "total_chunks": len(sub_chunks),
                    },
                })

    return chunks


def _tokenize(text: str) -> list[str]:
    """Simple tokenizer for BM25."""
    # Convert to lowercase and extract words
    return re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', text.lower())


def _compute_bm25_scores(query: str, chunks: list[dict]) -> list[tuple[int, float]]:
    """Compute BM25 scores for chunks."""
    query_tokens = _tokenize(query)
    if not query_tokens:
        return [(i, 0.0) for i in range(len(chunks))]

    # Build document frequencies
    doc_freqs = Counter()
    doc_lengths = []
    tokenized_docs = []

    for chunk in chunks:
        text = chunk["text"] + " " + chunk["metadata"].get("section", "")
        tokens = _tokenize(text)
        tokenized_docs.append(tokens)
        doc_lengths.append(len(tokens))
        unique_tokens = set(tokens)
        for token in unique_tokens:
            doc_freqs[token] += 1

    N = len(chunks)
    avgdl = sum(doc_lengths) / N if N > 0 else 0

    # Compute scores
    scores = []
    for idx, (tokens, doc_len) in enumerate(zip(tokenized_docs, doc_lengths)):
        score = 0.0
        token_counts = Counter(tokens)

        for token in query_tokens:
            if token not in doc_freqs:
                continue

            # IDF
            df = doc_freqs[token]
            idf = math.log((N - df + 0.5) / (df + 0.5) + 1.0)

            # TF with saturation
            tf = token_counts[token]
            tf_component = (tf * (K1 + 1)) / (tf + K1 * (1 - B + B * doc_len / avgdl))

            score += idf * tf_component

        scores.append((idx, score))

    return scores


def _normalize_scores(scores: list[tuple[int, float]]) -> list[tuple[int, float]]:
    """Normalize scores to 0-1 range."""
    if not scores:
        return scores

    values = [s[1] for s in scores]
    min_val = min(values)
    max_val = max(values)

    if max_val == min_val:
        return [(idx, 0.5) for idx, _ in scores]

    return [(idx, (val - min_val) / (max_val - min_val)) for idx, val in scores]


def _hybrid_search(
    query: str,
    chunks: list[dict],
    embeddings: list[list[float]],
    n_results: int = 5,
    embedding_weight: float = 0.7,
    bm25_weight: float = 0.3,
) -> list[dict]:
    """Perform hybrid search combining embeddings and BM25."""

    # Get embedding scores
    try:
        query_embedding = _embed([query])[0]
        embedding_scores = [
            (i, _cosine_similarity(query_embedding, emb))
            for i, emb in enumerate(embeddings)
        ]
        embedding_scores = _normalize_scores(embedding_scores)
    except Exception:
        # Fall back to BM25 only
        embedding_scores = [(i, 0.0) for i in range(len(chunks))]
        embedding_weight = 0.0
        bm25_weight = 1.0

    # Get BM25 scores
    bm25_scores = _compute_bm25_scores(query, chunks)
    bm25_scores = _normalize_scores(bm25_scores)

    # Combine scores
    emb_dict = {idx: score for idx, score in embedding_scores}
    bm25_dict = {idx: score for idx, score in bm25_scores}

    combined_scores = []
    for i in range(len(chunks)):
        combined = embedding_weight * emb_dict.get(i, 0) + bm25_weight * bm25_dict.get(i, 0)
        combined_scores.append((combined, i))

    # Sort and return top results
    combined_scores.sort(reverse=True)

    results = []
    for score, idx in combined_scores[:n_results]:
        chunk = chunks[idx]
        results.append({
            "text": chunk["text"],
            "section": chunk["metadata"].get("section", ""),
            "source": chunk["metadata"].get("source", ""),
            "backend": chunk["metadata"].get("backend", "general"),
            "score": round(score, 4),
        })

    return results


def _load_store() -> dict | None:
    """Load existing vector store from disk."""
    if STORE_FILE.exists():
        return json.loads(STORE_FILE.read_text())
    return None


def _save_store(store: dict) -> None:
    """Save vector store to disk."""
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    STORE_FILE.write_text(json.dumps(store))


def ingest_docs() -> int:
    """Ingest all docs from docs/ directory into the vector store.

    Returns:
        Number of chunks ingested.
    """
    chunks = _load_and_chunk_docs()
    if not chunks:
        return 0

    if not _ollama_reachable():
        # Save chunks without embeddings for keyword fallback
        store = {"chunks": chunks, "embeddings": [], "version": "2.0"}
        _save_store(store)
        return len(chunks)

    texts = [c["text"] for c in chunks]
    embeddings = _embed(texts)

    store = {
        "chunks": chunks,
        "embeddings": embeddings,
        "version": "2.0",
    }
    _save_store(store)

    return len(chunks)


def _keyword_search(chunks: list[dict], query: str, n_results: int) -> list[dict]:
    """Enhanced keyword-based search with TF-IDF scoring."""
    # Use BM25 for better keyword matching
    scores = _compute_bm25_scores(query, chunks)
    scores.sort(key=lambda x: x[1], reverse=True)

    results = []
    for idx, score in scores[:n_results]:
        chunk = chunks[idx]
        results.append({
            "text": chunk["text"],
            "section": chunk["metadata"].get("section", ""),
            "source": chunk["metadata"].get("source", ""),
            "backend": chunk["metadata"].get("backend", "general"),
            "score": round(score, 4),
        })
    return results


def retrieve(
    query: str,
    n_results: int = 5,
    backend_filter: str | None = None,
    category_filter: str | None = None,
    hybrid: bool = True,
) -> list[dict]:
    """Retrieve relevant document chunks for a query.

    Uses hybrid search (embeddings + BM25) when Ollama is available,
    falls back to keyword search otherwise.

    Args:
        query: Natural language query about firewalls.
        n_results: Number of results to return.
        backend_filter: Optional filter by backend (nftables, iptables, opnsense, aws).
        category_filter: Optional filter by category (linux, bsd, cloud, general).
        hybrid: Whether to use hybrid search (True) or embeddings only (False).

    Returns:
        List of dicts with 'text', 'section', 'source', 'backend', and 'score' keys.
    """
    store = _load_store()
    if store is None:
        try:
            ingest_docs()
        except Exception:
            pass
        store = _load_store()
        if store is None:
            return []

    chunks = store["chunks"]
    embeddings = store.get("embeddings", [])

    # Apply metadata filters
    if backend_filter:
        chunks = [c for c in chunks if c["metadata"].get("backend") == backend_filter]
        if embeddings:
            # Filter embeddings to match chunks
            original_indices = [i for i, c in enumerate(store["chunks"])
                              if c["metadata"].get("backend") == backend_filter]
            embeddings = [embeddings[i] for i in original_indices]

    if category_filter:
        chunks = [c for c in chunks if c["metadata"].get("category") == category_filter]
        if embeddings:
            original_indices = [i for i, c in enumerate(store["chunks"])
                              if c["metadata"].get("category") == category_filter]
            embeddings = [embeddings[i] for i in original_indices]

    if not chunks:
        return []

    # Use keyword fallback if no embeddings or Ollama unreachable
    if not embeddings or not _ollama_reachable():
        return _keyword_search(chunks, query, n_results)

    try:
        if hybrid:
            return _hybrid_search(query, chunks, embeddings, n_results)
        else:
            # Embeddings only
            query_embedding = _embed([query])[0]
            scored = [
                (_cosine_similarity(query_embedding, emb), chunk)
                for chunk, emb in zip(chunks, embeddings)
            ]
            scored.sort(key=lambda x: x[0], reverse=True)

            results = []
            for score, chunk in scored[:n_results]:
                results.append({
                    "text": chunk["text"],
                    "section": chunk["metadata"].get("section", ""),
                    "source": chunk["metadata"].get("source", ""),
                    "backend": chunk["metadata"].get("backend", "general"),
                    "score": round(score, 4),
                })
            return results

    except (httpx.ConnectError, httpx.TimeoutException):
        return _keyword_search(chunks, query, n_results)


def get_stats() -> dict:
    """Get statistics about the vector store.
    
    Returns:
        Dict with document count, chunk count, backends, and categories.
    """
    store = _load_store()
    if not store:
        return {"status": "empty", "documents": 0, "chunks": 0}

    chunks = store.get("chunks", [])
    backends = set(c["metadata"].get("backend", "unknown") for c in chunks)
    categories = set(c["metadata"].get("category", "unknown") for c in chunks)
    sources = set(c["metadata"].get("source", "unknown") for c in chunks)

    return {
        "status": "ready",
        "version": store.get("version", "1.0"),
        "documents": len(sources),
        "chunks": len(chunks),
        "backends": sorted(backends),
        "categories": sorted(categories),
        "sources": sorted(sources),
        "has_embeddings": len(store.get("embeddings", [])) > 0,
        "ollama_available": _ollama_reachable(),
    }


def ingest_docs_cli() -> None:
    """CLI entry point for document ingestion."""
    count = ingest_docs()
    stats = get_stats()

    print(f"✓ Ingested {count} chunks from {stats['documents']} documents")
    print(f"\nBackends covered: {', '.join(stats['backends'])}")
    print(f"Categories: {', '.join(stats['categories'])}")

    if _ollama_reachable():
        print(f"\n✓ Embeddings generated using {_get_embed_model()}")
        print("✓ Hybrid search available (BM25 + embeddings)")
    else:
        print(f"\n⚠ Keyword-only mode (Ollama not available at {_get_ollama_host()})")


if __name__ == "__main__":
    ingest_docs_cli()
