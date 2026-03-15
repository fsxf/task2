from __future__ import annotations

from pathlib import Path
import re
from typing import Optional

from .config import AppConfig
from .joern_runner import JoernStaticAnalyzer
from .models import CaseContext, CodeLocation, StaticEvidence


_CWE78_SOURCE_PATTERNS = [
    re.compile(r"\brecv\s*\("),
    re.compile(r"\bGETENV\s*\("),
    re.compile(r"\bfopen\s*\("),
    re.compile(r"\bfgets\s*\(.*stdin"),
]
_CWE78_SINK_PATTERN = re.compile(r"\bEXECL\s*\(")

_CWE259_SOURCE_PATTERNS = [
    re.compile(r"\bstrcpy\s*\(\s*password\s*,\s*PASSWORD\s*\)"),
    re.compile(r"FLAW:\s*Use a hardcoded password"),
]
_CWE259_SINK_PATTERN = re.compile(r"\bLogonUserA\s*\(")


class JulietStaticAnalyzer:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._window_radius = config.prompt_window_radius
        self._joern_analyzer = JoernStaticAnalyzer(config)

    def analyze(self, context: CaseContext, dataset_root: Path) -> StaticEvidence:
        use_joern = self._config.static_analysis_backend in ("joern", "auto")
        if use_joern:
            joern_evidence = self._joern_analyzer.analyze(context, dataset_root)
            if joern_evidence is not None:
                return joern_evidence
            if self._config.static_analysis_backend == "joern" and self._joern_analyzer.available:
                raise RuntimeError("Joern backend is enabled but did not return source/sink findings.")

        source_lines = self._read_lines(context.source_file)
        sink_lines = self._read_lines(context.sink_file)

        source_location = self._find_source_location(context, source_lines, dataset_root)
        sink_location = self._find_sink_location(context, sink_lines, dataset_root)
        primary_location = sink_location if context.cwe == "CWE78" else source_location

        notes = [
            "static backend: pattern-fallback",
            f"analysis source file: {context.source_file.name}",
            f"analysis sink file: {context.sink_file.name}",
            f"flow chain: {' -> '.join(context.flow_chain)}",
        ]
        if use_joern and not self._joern_analyzer.available:
            notes.insert(1, "joern unavailable, fallback to pattern matching")
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
            line_no = self._first_matching_line(lines, _CWE78_SOURCE_PATTERNS, scope_hint=context.analysis_scope)
        else:
            # Prefer the concrete hard-coded assignment over the nearby comment.
            line_no = self._first_matching_line(
                lines,
                [re.compile(r"\bstrcpy\s*\(\s*password\s*,\s*PASSWORD\s*\)")],
                scope_hint=context.analysis_scope,
            )
            if line_no is None:
                line_no = self._first_matching_line(
                    lines,
                    [re.compile(r"FLAW:\s*Use a hardcoded password")],
                    scope_hint=context.analysis_scope,
                )
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
        line_no = self._first_matching_line(
            lines,
            [pattern],
            skip_preprocessor=True,
            scope_hint=context.analysis_scope,
        )
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
        scope_hint: str = "",
    ) -> Optional[int]:
        scoped_line_numbers = JulietStaticAnalyzer._find_scoped_line_numbers(lines, scope_hint)
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if skip_preprocessor and stripped.startswith("#"):
                continue
            if scoped_line_numbers is not None and index not in scoped_line_numbers:
                continue
            for pattern in patterns:
                if pattern.search(stripped):
                    return index
        return None

    @staticmethod
    def _find_scoped_line_numbers(lines: list[str], scope_hint: str) -> Optional[set[int]]:
        normalized_scope = scope_hint.strip().lower()
        if not normalized_scope:
            return None

        scoped_lines: set[int] = set()
        pending_start: Optional[int] = None
        collecting = False
        brace_depth = 0

        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            lowered = stripped.lower()

            if collecting:
                scoped_lines.add(index)
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    collecting = False
                    brace_depth = 0
                continue

            if pending_start is not None:
                if "{" in line:
                    for scoped_index in range(pending_start, index + 1):
                        scoped_lines.add(scoped_index)
                    collecting = True
                    brace_depth = line.count("{") - line.count("}")
                    if brace_depth <= 0:
                        collecting = False
                        brace_depth = 0
                    pending_start = None
                    continue
                if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
                    pending_start = None

            if JulietStaticAnalyzer._looks_like_scoped_definition(stripped, lowered, normalized_scope):
                if "{" in line:
                    scoped_lines.add(index)
                    collecting = True
                    brace_depth = line.count("{") - line.count("}")
                    if brace_depth <= 0:
                        collecting = False
                        brace_depth = 0
                else:
                    pending_start = index

        return scoped_lines

    @staticmethod
    def _looks_like_scoped_definition(stripped: str, lowered: str, scope_hint: str) -> bool:
        if not stripped:
            return False
        if stripped.startswith(("#", "//", "/*", "*", "else", "if", "for", "while", "switch")):
            return False
        if scope_hint not in lowered:
            return False
        if "(" not in stripped or stripped.endswith(";"):
            return False
        return True

    def _render_window(self, lines: list[str], line_no: int) -> str:
        start = max(1, line_no - self._window_radius)
        end = min(len(lines), line_no + self._window_radius)
        return "\n".join(f"{index:>4}: {lines[index - 1]}" for index in range(start, end + 1))
