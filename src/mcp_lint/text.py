"""Small text helpers: name splitting, token estimates, TF-IDF similarity.

Standard library only, so the static rules run offline with no API key.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter

from mcp_lint.models import ToolDef

CHARS_PER_TOKEN = 4  # rough offline estimate; label it as such in reports

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SEP = re.compile(r"[_\-.\s/:]+")
_WORD = re.compile(r"[a-z0-9]+")

_STOPWORDS = frozenset(
    "a an and are as at be by can for from has have if in into is it its of on or "
    "that the this to was will with you your use used using tool returns return".split()
)


def split_name(name: str) -> list[str]:
    """'github_listPullRequests' -> ['github', 'list', 'pull', 'requests']."""
    parts: list[str] = []
    for chunk in _SEP.split(name):
        parts.extend(p.lower() for p in _CAMEL.split(chunk) if p)
    return parts


def naming_style(name: str) -> str | None:
    """Return the separator style of a multi-word name, or None for one word."""
    if "_" in name:
        return "snake_case"
    if "-" in name:
        return "kebab-case"
    if "." in name:
        return "dot.case"
    if _CAMEL.search(name):
        return "camelCase"
    return None


def definition_json(tool: ToolDef) -> str:
    return json.dumps(
        {"name": tool.name, "description": tool.description or "", "inputSchema": tool.input_schema},
        separators=(",", ":"),
    )


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def _terms(tool: ToolDef) -> list[str]:
    words = split_name(tool.name) + _WORD.findall((tool.description or "").lower())
    return [w for w in words if w not in _STOPWORDS and len(w) > 1]


def similarity_matrix(tools: list[ToolDef]) -> list[list[float]]:
    """Pairwise cosine similarity of TF-IDF vectors over name + description."""
    docs = [Counter(_terms(t)) for t in tools]
    n = len(docs)
    df: Counter[str] = Counter()
    for d in docs:
        df.update(d.keys())
    idf = {w: math.log((1 + n) / (1 + c)) + 1 for w, c in df.items()}
    vecs = []
    for d in docs:
        v = {w: tf * idf[w] for w, tf in d.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        vecs.append({w: x / norm for w, x in v.items()})
    sims = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            a, b = vecs[i], vecs[j]
            if len(a) > len(b):
                a, b = b, a
            s = sum(x * b.get(w, 0.0) for w, x in a.items())
            sims[i][j] = sims[j][i] = s
    return sims
