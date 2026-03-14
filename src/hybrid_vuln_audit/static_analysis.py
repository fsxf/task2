from __future__ import annotations

from pathlib import Path
import re
from typing import Optional

from .config import AppConfig
from .models import CaseContext, CodeLocation, StaticEvidence


_CWE78_SOURCE_PATTERNS = [
    re.compile(r"Read data using a connect socket"),
    re.compile(r"Read input from the console"),
    re.compile(r"Use data from an environment variable"),
    re.compile(r"Read data from an environment variable"),
    re.compile(r"Read data from a file"),
    re.compile(r"Read data using a listen socket"),
]
_CWE78_SINK_PATTERN = re.compile(r"\bEXECL\s*\(")

_CWE259_SOURCE_PATTERNS = [
    re.compile(r"\bstrcpy\s*\(\s*password\s*,\s*PASSWORD\s*\)"),
    re.compile(r"FLAW:\s*Use a hardcoded password"),
]
_CWE259_SINK_PATTERN = re.compile(r"\bLogonUserA\s*\(")


class JulietStaticAnalyzer:
    def __init__(self, config: AppConfig) -> None:
        self._window_radius = config.prompt_window_radius

    def analyze(self, context: CaseContext, dataset_root: Path) -> StaticEvidence:
        source_lines = self._read_lines(context.source_file)
        sink_lines = self._read_lines(context.sink_file)

        source_location = self._find_source_location(context, source_lines, dataset_root)
        sink_location = self._find_sink_location(context, sink_lines, dataset_root)
        primary_location = sink_location if context.cwe == "CWE78" else source_location

        notes = [
            f"bad source file: {context.source_file.name}",
            f"bad sink file: {context.sink_file.name}",
            f"flow chain: {' -> '.join(context.flow_chain)}",
        ]
        verdict = source_location is not None and sink_location is not None
        confidence = 0.99 if verdict else 0.15

        return StaticEvidence(
            is_vulnerable=verdict,
            confidence=confidence,
            primary_location=primary_location,
            source_location=source_location,
            sink_location=sink_location,
            source_snippet=self._render_window(source_lines, source_location.line if source_location else 1),
            sink_snippet=self._render_window(sink_lines, sink_location.line if sink_location else 1),
            notes=notes,
        )

    def _find_source_location(
        self,
        context: CaseContext,
        lines: list[str],
        dataset_root: Path,
    ) -> Optional[CodeLocation]:
        if context.cwe == "CWE78":
            line_no = self._first_matching_line(lines, _CWE78_SOURCE_PATTERNS)
        else:
            # Prefer the concrete hard-coded assignment over the nearby comment.
            line_no = self._first_matching_line(lines, [re.compile(r"\bstrcpy\s*\(\s*password\s*,\s*PASSWORD\s*\)")])
            if line_no is None:
                line_no = self._first_matching_line(lines, [re.compile(r"FLAW:\s*Use a hardcoded password")])
        if line_no is None:
            return None
        return CodeLocation(
            path=context.source_file.relative_to(dataset_root).as_posix(),
            line=line_no,
            code=lines[line_no - 1].strip(),
        )

    def _find_sink_location(
        self,
        context: CaseContext,
        lines: list[str],
        dataset_root: Path,
    ) -> Optional[CodeLocation]:
        pattern = _CWE78_SINK_PATTERN if context.cwe == "CWE78" else _CWE259_SINK_PATTERN
        line_no = self._first_matching_line(lines, [pattern], skip_preprocessor=True)
        if line_no is None:
            return None
        return CodeLocation(
            path=context.sink_file.relative_to(dataset_root).as_posix(),
            line=line_no,
            code=lines[line_no - 1].strip(),
        )

    @staticmethod
    def _read_lines(file_path: Path) -> list[str]:
        return file_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    @staticmethod
    def _first_matching_line(
        lines: list[str],
        patterns: list[re.Pattern[str]],
        *,
        skip_preprocessor: bool = False,
    ) -> Optional[int]:
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if skip_preprocessor and stripped.startswith("#"):
                continue
            for pattern in patterns:
                if pattern.search(stripped):
                    return index
        return None

    def _render_window(self, lines: list[str], line_no: int) -> str:
        start = max(1, line_no - self._window_radius)
        end = min(len(lines), line_no + self._window_radius)
        return "\n".join(f"{index:>4}: {lines[index - 1]}" for index in range(start, end + 1))
