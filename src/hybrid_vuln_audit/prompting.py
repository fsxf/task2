from __future__ import annotations

from typing import Tuple

from .models import CaseContext, StaticEvidence


def build_messages(context: CaseContext, evidence: StaticEvidence) -> Tuple[str, str]:
    system_prompt = (
        "You are a senior vulnerability auditor. "
        "Judge only the BAD path in the supplied evidence. "
        "Return a compact JSON object with keys: verdict, confidence, primary_line, source_line, sink_line, reason."
    )

    user_prompt = f"""
Case: {context.case_id}
CWE: {context.cwe}
Variant: {context.variant}
Flow chain: {' -> '.join(context.flow_chain)}

Static verdict: {evidence.is_vulnerable}
Static confidence: {evidence.confidence:.2f}

Primary location:
{_location_text(evidence.primary_location)}

Source location:
{_location_text(evidence.source_location)}

Sink location:
{_location_text(evidence.sink_location)}

Source snippet:
{evidence.source_snippet}

Sink snippet:
{evidence.sink_snippet}

Notes:
{chr(10).join(f"- {note}" for note in evidence.notes)}
""".strip()

    return system_prompt, user_prompt


def _location_text(location) -> str:
    if location is None:
        return "none"
    return f"{location.path}:{location.line} -> {location.code}"
