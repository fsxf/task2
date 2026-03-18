from __future__ import annotations

import re
from typing import Tuple

from .models import CaseContext, StaticEvidence


def build_messages(context: CaseContext, evidence: StaticEvidence) -> Tuple[str, str]:
    sanitizer = _PromptSanitizer()
    system_prompt = (
        "You are a senior vulnerability auditor. "
        "Review the supplied candidate source, sink, and propagation evidence. "
        "Do not assume the candidate is a real vulnerability unless the code evidence supports it. "
        "Return a compact JSON object with keys: verdict, confidence, primary_line, source_line, sink_line, reason."
    )

    user_prompt = f"""
CWE family: {context.cwe}
Variant: {context.variant}

Candidate primary location:
{_location_text(evidence.primary_location, sanitizer)}

Candidate source location:
{_location_text(evidence.source_location, sanitizer)}

Candidate sink location:
{_location_text(evidence.sink_location, sanitizer)}

Candidate source snippet:
{sanitizer.sanitize_text(evidence.source_snippet) or "none"}

Candidate sink snippet:
{sanitizer.sanitize_text(evidence.sink_snippet) or "none"}

Analysis notes:
{_evidence_lines(_filtered_notes(evidence.notes), sanitizer)}

Propagation evidence:
{_evidence_lines(_filtered_flow_evidence(evidence.flow_evidence), sanitizer)}
""".strip()

    return system_prompt, user_prompt


def _location_text(location, sanitizer: "_PromptSanitizer") -> str:
    if location is None:
        return "none"
    return "{0}:{1} -> {2}".format(
        sanitizer.sanitize_text(location.path),
        location.line,
        sanitizer.sanitize_text(location.code),
    )


def _evidence_lines(items: list[str], sanitizer: "_PromptSanitizer") -> str:
    if not items:
        return "none"
    return chr(10).join(f"- {sanitizer.sanitize_text(item)}" for item in items)


def _filtered_notes(items: list[str]) -> list[str]:
    filtered: list[str] = []
    hidden_prefixes = (
        "flow chain:",
        "benchmark flow chain:",
        "joern project:",
        "joern workspace root:",
        "joern case input root:",
    )
    for item in items:
        lowered = item.strip().lower()
        if any(lowered.startswith(prefix) for prefix in hidden_prefixes):
            continue
        filtered.append(item)
    return filtered


def _filtered_flow_evidence(items: list[str]) -> list[str]:
    filtered: list[str] = []
    for item in items:
        lowered = item.strip().lower()
        if lowered.startswith("benchmark flow chain:"):
            continue
        filtered.append(item)
    return filtered


_BLOCK_COMMENT_PATTERN = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_PATTERN = re.compile(r"//.*?$", re.MULTILINE)
_IDENTIFIER_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


class _PromptSanitizer:
    def __init__(self) -> None:
        self._token_map: dict[str, str] = {}
        self._counter = 0

    def sanitize_text(self, text: str) -> str:
        if not text:
            return ""
        text = _BLOCK_COMMENT_PATTERN.sub("", text)
        text = _LINE_COMMENT_PATTERN.sub("", text)
        text = _IDENTIFIER_PATTERN.sub(self._replace_identifier, text)
        return "\n".join(line.rstrip() for line in text.splitlines()).strip()

    def _replace_identifier(self, match: re.Match[str]) -> str:
        token = match.group(0)
        if not _should_redact_identifier(token):
            return token
        if token not in self._token_map:
            self._counter += 1
            self._token_map[token] = f"symbol_{self._counter}"
        return self._token_map[token]


def _should_redact_identifier(token: str) -> bool:
    lowered = token.lower()
    if lowered in {"bad", "good", "goodg2b", "goodb2g", "flaw", "fix"}:
        return True
    if "goodg2b" in lowered or "goodb2g" in lowered:
        return True
    if "bad" in lowered and ("_" in token or "sink" in lowered or "source" in lowered):
        return True
    if "good" in lowered and ("_" in token or "sink" in lowered or "source" in lowered):
        return True
    return False
