"""Local RAG knowledge base: Document -> Chunk -> Vectorize (TF-IDF) -> Store (in memory) -> Retrieve.

TF-IDF keeps the project dependency-free and fully explainable. The `Retriever` interface
(`search(query, k)`) is what the AI layer uses, so swapping in ChromaDB + Ollama embeddings later
only means replacing this class.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_STOP = set("a an and are as at be by for from has have in is it its of on or that the this to was were will with not can".split())


def tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_.:*-]+", text.lower()) if t not in _STOP and len(t) > 1]


@dataclass
class Chunk:
    source: str
    heading: str
    text: str


def chunk_markdown(source: str, text: str) -> list[Chunk]:
    """Split on '## ' headings so each chunk is one self-contained topic."""
    chunks, heading, buf = [], source, []
    for line in text.splitlines():
        if line.startswith("## "):
            if buf and "".join(buf).strip():
                chunks.append(Chunk(source, heading, "\n".join(buf).strip()))
            heading, buf = line[3:].strip(), []
        elif not line.startswith("# "):
            buf.append(line)
    if buf and "".join(buf).strip():
        chunks.append(Chunk(source, heading, "\n".join(buf).strip()))
    return chunks


class Retriever:
    def __init__(self, knowledge_dir: Path):
        self.chunks: list[Chunk] = []
        for p in sorted(Path(knowledge_dir).glob("*.md")):
            self.chunks.extend(chunk_markdown(p.name, p.read_text(encoding="utf-8")))
        docs = [Counter(tokenize(c.heading + " " + c.text)) for c in self.chunks]
        n = max(1, len(docs))
        df = Counter(t for d in docs for t in d)
        self.idf = {t: math.log((1 + n) / (1 + c)) + 1 for t, c in df.items()}
        self.vecs = [self._vec(d) for d in docs]

    def _vec(self, counts: Counter) -> dict[str, float]:
        v = {t: (1 + math.log(c)) * self.idf.get(t, 0.0) for t, c in counts.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def search(self, query: str, k: int = 3, min_score: float = 0.08) -> list[tuple[Chunk, float]]:
        q = self._vec(Counter(tokenize(query)))
        scored = [(c, sum(w * v.get(t, 0.0) for t, w in q.items())) for c, v in zip(self.chunks, self.vecs)]
        scored = [s for s in sorted(scored, key=lambda s: s[1], reverse=True) if s[1] >= min_score]
        return scored[:k]
