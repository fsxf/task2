from __future__ import annotations

import math


def estimate_text_tokens(text: str) -> int:
    """Approximate BPE-style token usage with a simple byte heuristic."""
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / 4))
