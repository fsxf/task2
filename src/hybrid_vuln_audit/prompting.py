from __future__ import annotations

from typing import Tuple

from .models import CaseContext, StaticEvidence


def build_messages(context: CaseContext, evidence: StaticEvidence) -> Tuple[str, str]:
    system_prompt = (
        "You are a senior vulnerability auditor. "
        "Use only the supplied function bodies to decide whether there is a real vulnerability. "
        "Return a compact JSON object with keys: verdict, reason."
    )

    user_prompt = f"""
Function bodies:
{_function_blocks(evidence.function_evidence)}
""".strip()

    return system_prompt, user_prompt

def _function_blocks(items: list[str]) -> str:
    if not items:
        return "none"
    return chr(10).join(items)
