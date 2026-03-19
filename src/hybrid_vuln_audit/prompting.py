from __future__ import annotations

from typing import Tuple

from .models import CaseContext, StaticEvidence


def build_messages(context: CaseContext, evidence: StaticEvidence) -> Tuple[str, str]:
    system_prompt = (
        "You are a senior vulnerability auditor. "
        "Use only the supplied function bodies to decide whether there is a real OS command injection (untrusted input to cmd) or hard-coded auth credential vulnerability. "
        "Return ONLY one compact JSON object with keys: verdict(a JSON boolean: true or false), reason(very brief). "
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
