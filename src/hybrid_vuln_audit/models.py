from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CodeLocation:
    path: str
    line: int
    code: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CaseContext:
    case_id: str
    cwe: str
    variant: str
    source_kind: str
    root_file: Path
    group_files: list[Path]
    source_file: Path
    sink_file: Path
    flow_chain: list[str]
    expected_vulnerable: bool = True
    analysis_scope: str = "bad"

    def relative_root(self, base: Path) -> str:
        return self.root_file.relative_to(base).as_posix()


@dataclass
class StaticEvidence:
    is_vulnerable: bool
    confidence: float
    primary_location: Optional[CodeLocation]
    source_location: Optional[CodeLocation]
    sink_location: Optional[CodeLocation]
    source_snippet: str
    sink_snippet: str
    notes: list[str] = field(default_factory=list)
    flow_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "primary_location": self.primary_location.to_dict() if self.primary_location else None,
            "source_location": self.source_location.to_dict() if self.source_location else None,
            "sink_location": self.sink_location.to_dict() if self.sink_location else None,
            "source_snippet": self.source_snippet,
            "sink_snippet": self.sink_snippet,
            "notes": self.notes,
            "flow_evidence": self.flow_evidence,
        }


@dataclass
class LLMReview:
    verdict: bool
    confidence: float
    reason: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    model: str
    mode: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisResult:
    case_id: str
    cwe: str
    variant: str
    root_file: str
    vulnerable: bool
    expected_vulnerable: bool
    correct: bool
    primary_location: Optional[CodeLocation]
    source_location: Optional[CodeLocation]
    sink_location: Optional[CodeLocation]
    flow_chain: list[str]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    llm_mode: str
    llm_model: str
    reason: str
    static_confidence: float
    review_confidence: float
    notes: list[str]
    flow_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "cwe": self.cwe,
            "variant": self.variant,
            "root_file": self.root_file,
            "vulnerable": self.vulnerable,
            "expected_vulnerable": self.expected_vulnerable,
            "correct": self.correct,
            "primary_location": self.primary_location.to_dict() if self.primary_location else None,
            "source_location": self.source_location.to_dict() if self.source_location else None,
            "sink_location": self.sink_location.to_dict() if self.sink_location else None,
            "flow_chain": self.flow_chain,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "llm_mode": self.llm_mode,
            "llm_model": self.llm_model,
            "reason": self.reason,
            "static_confidence": self.static_confidence,
            "review_confidence": self.review_confidence,
            "notes": self.notes,
            "flow_evidence": self.flow_evidence,
        }
