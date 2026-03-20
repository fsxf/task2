from __future__ import annotations

from dataclasses import asdict, dataclass
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
    primary_location: Optional[CodeLocation]
    source_location: Optional[CodeLocation]
    sink_location: Optional[CodeLocation]
    function_evidence: list[str]


@dataclass
class LLMReview:
    verdict: bool
    reason: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

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
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    reason: str

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
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "reason": self.reason,
        }
