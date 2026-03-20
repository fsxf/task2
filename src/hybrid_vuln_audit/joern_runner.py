from __future__ import annotations

import base64
from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional

from .config import AppConfig
from .models import CaseContext, CodeLocation, StaticEvidence


@dataclass
class _JoernFinding:
    kind: str
    path: str
    line: int
    call_name: str
    method_name: str
    code: str


@dataclass
class _JoernCallEdge:
    path: str
    line: int
    caller: str
    callee: str
    code: str


@dataclass
class _JoernMethodDef:
    path: str
    start_line: int
    end_line: int
    full_name: str
    code: str


class JoernStaticAnalyzer:
    _CODE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}
    _SYSTEM_INCLUDE_LINE_PATTERN = re.compile(r"^\s*#\s*include\s*<.*?>\s*$")
    _MARKER_PATTERN = re.compile(r"^\s*#\s+\d+\s+.*$", re.MULTILINE)

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._cli_path = self._resolve_cli_path(config.joern_cli_path)
        self._joern_home = self._cli_path.parent if self._cli_path is not None else None

    @property
    def available(self) -> bool:
        return self._cli_path is not None and self._config.joern_script_path.exists()

    def analyze(self, context: CaseContext, dataset_root: Path) -> Optional[StaticEvidence]:
        if not self.available:
            return None

        case_temp_root = self._config.joern_case_temp_root.resolve()
        case_temp_root.mkdir(parents=True, exist_ok=True)
        project_name = self._build_project_name(context)

        temp_path, line_maps = self._prepare_kept_case_directory(case_temp_root, project_name, context)
        findings = self._analyze_with_joern(temp_path, context, dataset_root, project_name, line_maps)

        source_finding = self._pick_best_finding(findings, "SOURCE", context.analysis_scope)
        sink_finding = self._pick_best_finding(findings, "SINK", context.analysis_scope)
        source_location = self._to_location(source_finding)
        sink_location = self._to_location(sink_finding)
        primary_location = sink_location if context.cwe == "CWE78" else source_location

        call_edges = self._extract_call_edges(findings)
        method_defs = self._extract_method_defs(findings, temp_path)
        chain_methods = self._derive_chain_methods(call_edges, source_finding, sink_finding)
        chain_methods = self._expand_chain_with_source_plus_one(chain_methods, call_edges, source_finding)

        sanitizer = _JulietFunctionSanitizer()
        sanitizer.learn(chain_methods, method_defs)
        self._sanitize_locations(sanitizer, source_location, sink_location, primary_location)

        function_evidence = self._build_function_evidence(chain_methods, method_defs, sanitizer)
        verdict = source_location is not None and sink_location is not None

        return StaticEvidence(
            is_vulnerable=verdict,
            primary_location=primary_location,
            source_location=source_location,
            sink_location=sink_location,
            function_evidence=function_evidence,
        )

    def _analyze_with_joern(
        self,
        temp_path: Path,
        context: CaseContext,
        dataset_root: Path,
        project_name: str,
        line_maps: dict[str, dict[int, int]],
    ) -> List[_JoernFinding]:
        findings_path = temp_path / "findings.tsv"
        self._run_joern(
            input_path=temp_path,
            findings_path=findings_path,
            cwe=context.cwe,
            variant=context.variant,
            analysis_scope=context.analysis_scope,
            project_name=project_name,
        )
        return self._parse_findings(findings_path, context, dataset_root, line_maps)

    def _select_case_files(self, context: CaseContext) -> List[Path]:
        unique: List[Path] = []
        seen = set()
        for item in context.group_files:
            key = str(item.resolve())
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    def _run_joern(
        self,
        input_path: Path,
        findings_path: Path,
        cwe: str,
        variant: str,
        analysis_scope: str,
        project_name: str,
    ) -> None:
        command = self._build_command(
            input_path=input_path,
            findings_path=findings_path,
            cwe=cwe,
            variant=variant,
            analysis_scope=analysis_scope,
            project_name=project_name,
        )
        env = None
        if self._config.java_home is not None:
            env = dict(os.environ)
            env["JAVA_HOME"] = str(self._config.java_home)
            env["PATH"] = "{0};{1}".format(str((self._config.java_home / "bin").resolve()), env.get("PATH", ""))

        joern_runtime_root = self._config.joern_workspace_root.resolve()
        joern_runtime_root.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            command,
            cwd=str(joern_runtime_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env,
        )
        if completed.returncode != 0:
            raise RuntimeError("Joern execution failed: {0}".format(completed.stderr.strip() or completed.stdout.strip()))

    def _build_project_name(self, context: CaseContext) -> str:
        # Keep one stable CPG project per Juliet case id.
        return self._sanitize_name(context.case_id)

    def _prepare_kept_case_directory(
        self,
        case_temp_root: Path,
        project_name: str,
        context: CaseContext,
    ) -> tuple[Path, dict[str, dict[int, int]]]:
        case_dir = case_temp_root / project_name
        if case_dir.exists():
            shutil.rmtree(str(case_dir), ignore_errors=True)
        case_dir.mkdir(parents=True, exist_ok=True)

        selected_files = self._select_case_files(context)
        include_dirs = sorted({str(item.parent.resolve()) for item in selected_files})
        line_maps: dict[str, dict[int, int]] = {}

        for file_path in selected_files:
            target = case_dir / file_path.name
            if file_path.suffix.lower() in self._CODE_EXTENSIONS:
                ok, line_map = self._preprocess_code_file(file_path, target, include_dirs)
                if line_map:
                    line_maps[file_path.name] = line_map
                if not ok:
                    shutil.copy2(str(file_path), str(target))
            else:
                shutil.copy2(str(file_path), str(target))

        return case_dir, line_maps

    def _preprocess_code_file(
        self,
        source: Path,
        target: Path,
        include_dirs: list[str],
    ) -> tuple[bool, dict[int, int]]:
        compiler = "g++" if source.suffix.lower() in {".cpp", ".cxx", ".cc"} else "gcc"
        raw = source.read_text(encoding="utf-8", errors="ignore")
        raw_lines = raw.splitlines()
        filtered_lines: list[str] = []
        temp_to_original_line: dict[int, int] = {}
        for original_index, line in enumerate(raw_lines, start=1):
            if self._SYSTEM_INCLUDE_LINE_PATTERN.match(line):
                continue
            filtered_lines.append(line)
            temp_to_original_line[len(filtered_lines)] = original_index

        with tempfile.NamedTemporaryFile("w", suffix=source.suffix, delete=False, encoding="utf-8") as temp_file:
            temp_file.write("\n".join(filtered_lines))
            temp_input = Path(temp_file.name)

        cmd = [compiler, "-E", str(temp_input)]
        for include_dir in include_dirs:
            cmd.extend(["-I", include_dir])

        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=90,
            )
        except FileNotFoundError:
            self._safe_unlink(temp_input)
            return False, {}
        except subprocess.TimeoutExpired:
            self._safe_unlink(temp_input)
            return False, {}

        self._safe_unlink(temp_input)

        if completed.returncode != 0:
            return False, {}

        aliases = {source.name, temp_input.name}
        preprocessed, line_map = self._strip_markers_and_build_line_map(completed.stdout, aliases, temp_to_original_line)
        target.write_text(preprocessed, encoding="utf-8")
        return True, line_map

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass

    @staticmethod
    def _strip_markers_and_build_line_map(
        preprocessed: str,
        source_aliases: set[str],
        temp_to_original_line: dict[int, int],
    ) -> tuple[str, dict[int, int]]:
        marker_pattern = re.compile(r'^\s*#\s+(\d+)\s+"([^"]+)"(?:\s+.*)?$')
        emitted_lines: list[str] = []
        line_map: dict[int, int] = {}
        current_file_name = ""
        current_source_line = -1

        for raw_line in preprocessed.splitlines():
            marker_match = marker_pattern.match(raw_line)
            if marker_match:
                current_source_line = int(marker_match.group(1))
                current_file_name = Path(marker_match.group(2)).name
                continue

            emitted_lines.append(raw_line)
            emitted_index = len(emitted_lines)
            if current_source_line > 0 and current_file_name in source_aliases:
                line_map[emitted_index] = temp_to_original_line.get(current_source_line, current_source_line)
            if current_source_line > 0:
                current_source_line += 1

        return "\n".join(emitted_lines), line_map

    @staticmethod
    def _build_java_command(java_executable: str, joern_home: Path) -> List[str]:
        classpath = str((joern_home / "lib").resolve()) + "\\*"
        return [
            java_executable,
            "-Dlog4j.configurationFile={0}".format((joern_home / "conf" / "log4j2.xml").resolve()),
            "-cp",
            classpath,
            "io.joern.joerncli.console.ReplBridge",
        ]

    def _build_command(
        self,
        input_path: Path,
        findings_path: Path,
        cwe: str,
        variant: str,
        analysis_scope: str,
        project_name: str,
    ) -> List[str]:
        java_executable = "java"
        if self._config.java_home is not None:
            java_executable = str((self._config.java_home / "bin" / "java.exe").resolve())
        if self._joern_home is None:
            raise RuntimeError("Joern CLI path is not configured.")

        return self._build_java_command(java_executable, self._joern_home) + [
            "--script",
            str(self._config.joern_script_path),
            "--param",
            "inputPath={0}".format(input_path),
            "--param",
            "projectName={0}".format(project_name),
            "--param",
            "cwe={0}".format(cwe),
            "--param",
            "variant={0}".format(variant),
            "--param",
            "analysisScope={0}".format(analysis_scope),
            "--param",
            "outFile={0}".format(findings_path),
        ]

    @staticmethod
    def _resolve_cli_path(configured_path: Optional[Path]) -> Optional[Path]:
        if configured_path is not None and configured_path.exists():
            return configured_path
        for candidate in ("joern", "joern.bat"):
            resolved = shutil.which(candidate)
            if resolved:
                return Path(resolved).resolve()
        return None

    def _parse_findings(
        self,
        findings_path: Path,
        context: CaseContext,
        dataset_root: Path,
        line_maps: dict[str, dict[int, int]],
    ) -> List[_JoernFinding]:
        if not findings_path.exists():
            return []
        rows: List[_JoernFinding] = []
        for raw_line in findings_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = raw_line.split("\t", 5)
            if len(parts) != 6:
                continue
            kind, relative_path, line, call_name, method_name, code = parts
            mapped_path = self._map_temp_path_to_dataset(relative_path, context, dataset_root)
            if mapped_path is None:
                continue
            resolved_line = int(line)
            if kind != "METHOD":
                per_file_map = line_maps.get(Path(relative_path).name)
                if per_file_map:
                    resolved_line = per_file_map.get(resolved_line, resolved_line)
            rows.append(
                _JoernFinding(
                    kind=kind,
                    path=mapped_path,
                    line=resolved_line,
                    call_name=call_name,
                    method_name=method_name,
                    code=code,
                )
            )
        return rows

    def _map_temp_path_to_dataset(self, reported_path: str, context: CaseContext, dataset_root: Path) -> Optional[str]:
        report_name = Path(reported_path).name
        for candidate in context.group_files:
            if candidate.name == report_name:
                return candidate.relative_to(dataset_root).as_posix()
        return None

    def _pick_best_finding(self, findings: List[_JoernFinding], kind: str, analysis_scope: str) -> Optional[_JoernFinding]:
        candidates = [finding for finding in findings if finding.kind == kind]
        if not candidates:
            return None
        scoped_candidates = [finding for finding in candidates if analysis_scope.lower() in finding.method_name.lower()]
        return scoped_candidates[0] if scoped_candidates else candidates[0]

    @staticmethod
    def _to_location(finding: Optional[_JoernFinding]) -> Optional[CodeLocation]:
        if finding is None:
            return None
        return CodeLocation(path=finding.path, line=finding.line, code=finding.code)

    @staticmethod
    def _extract_call_edges(findings: List[_JoernFinding]) -> List[_JoernCallEdge]:
        edges: List[_JoernCallEdge] = []
        seen = set()
        for finding in findings:
            if finding.kind != "CALL_EDGE":
                continue
            key = (finding.path, finding.line, finding.call_name, finding.method_name, finding.code)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                _JoernCallEdge(
                    path=finding.path,
                    line=finding.line,
                    caller=finding.call_name,
                    callee=finding.method_name,
                    code=finding.code,
                )
            )
        return edges

    @staticmethod
    def _extract_method_defs(findings: List[_JoernFinding], case_input_dir: Path) -> dict[str, _JoernMethodDef]:
        method_defs: dict[str, _JoernMethodDef] = {}
        for finding in findings:
            if finding.kind != "METHOD":
                continue
            try:
                decoded = base64.b64decode(finding.code.encode("utf-8")).decode("utf-8", errors="ignore")
            except Exception:
                decoded = ""
            try:
                end_line = int(finding.call_name)
            except ValueError:
                end_line = finding.line
            full_code = JoernStaticAnalyzer._extract_method_body_from_preprocessed(
                case_input_dir=case_input_dir,
                dataset_relative_path=finding.path,
                start_line=finding.line,
                end_line=end_line,
                fallback_code=decoded,
            )
            method_defs[finding.method_name] = _JoernMethodDef(
                path=finding.path,
                start_line=finding.line,
                end_line=end_line,
                full_name=finding.method_name,
                code=full_code,
            )
        return method_defs

    def _derive_chain_methods(
        self,
        call_edges: List[_JoernCallEdge],
        source_finding: Optional[_JoernFinding],
        sink_finding: Optional[_JoernFinding],
    ) -> list[str]:
        if source_finding is None or sink_finding is None:
            return []

        source_method = source_finding.method_name
        sink_method = sink_finding.method_name
        if source_method == sink_method:
            return [source_method]

        directed_path = self._find_method_path(call_edges, source_method, sink_method, directed=True)
        if directed_path:
            return self._path_to_methods(directed_path)

        reverse_path = self._find_method_path(call_edges, sink_method, source_method, directed=True)
        if reverse_path:
            methods = self._path_to_methods(reverse_path)
            methods.reverse()
            return methods

        structural_path = self._find_method_path(call_edges, source_method, sink_method, directed=False)
        if structural_path:
            return self._path_to_methods(structural_path)

        if source_method != sink_method:
            return [source_method, sink_method]
        return [source_method]

    @staticmethod
    def _expand_chain_with_source_plus_one(
        chain_methods: list[str],
        call_edges: List[_JoernCallEdge],
        source_finding: Optional[_JoernFinding],
    ) -> list[str]:
        if not chain_methods or source_finding is None:
            return chain_methods

        source_method = source_finding.method_name
        direct_callers: list[str] = []
        seen_callers: set[str] = set()
        for edge in call_edges:
            if edge.callee != source_method:
                continue
            caller = edge.caller
            if not caller or caller == source_method or caller in seen_callers:
                continue
            seen_callers.add(caller)
            direct_callers.append(caller)

        if not direct_callers:
            return chain_methods

        merged: list[str] = []
        seen: set[str] = set()
        for method_name in direct_callers + chain_methods:
            if not method_name or method_name in seen:
                continue
            seen.add(method_name)
            merged.append(method_name)
        return merged

    @staticmethod
    def _path_to_methods(path: List[tuple[_JoernCallEdge, bool]]) -> list[str]:
        if not path:
            return []
        methods = [path[0][0].caller if path[0][1] else path[0][0].callee]
        for edge, is_forward in path:
            methods.append(edge.callee if is_forward else edge.caller)
        return methods

    def _build_function_evidence(
        self,
        chain_methods: list[str],
        method_defs: dict[str, _JoernMethodDef],
        sanitizer: "_JulietFunctionSanitizer",
    ) -> list[str]:
        blocks: list[str] = []
        for index, method_name in enumerate(chain_methods, start=1):
            method_def = method_defs.get(method_name)
            if method_def is None:
                blocks.append(
                    "Function {0}: {1}\n<missing method body in Joern export>".format(
                        index,
                        sanitizer.sanitize_method_name(method_name),
                    )
                )
                continue
            code = sanitizer.sanitize_code(method_def.code)
            blocks.append(
                "Function {0}: {1}\n{2}".format(
                    index,
                    sanitizer.sanitize_method_name(method_name),
                    code.strip() or "<empty>",
                )
            )
        return blocks

    @staticmethod
    def _find_method_path(
        edges: List[_JoernCallEdge],
        start_method: str,
        target_method: str,
        *,
        directed: bool,
    ) -> List[tuple[_JoernCallEdge, bool]]:
        if not start_method or not target_method:
            return []

        adjacency: dict[str, List[tuple[str, _JoernCallEdge, bool]]] = {}
        for edge in edges:
            adjacency.setdefault(edge.caller, []).append((edge.callee, edge, True))
            if not directed:
                adjacency.setdefault(edge.callee, []).append((edge.caller, edge, False))

        queue: deque[tuple[str, List[tuple[_JoernCallEdge, bool]]]] = deque([(start_method, [])])
        visited = {start_method}

        while queue:
            current_method, path = queue.popleft()
            if current_method == target_method:
                return path
            for next_method, edge, is_forward in adjacency.get(current_method, []):
                if next_method in visited:
                    continue
                visited.add(next_method)
                queue.append((next_method, path + [(edge, is_forward)]))

        return []

    @staticmethod
    def _sanitize_name(value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value)

    @staticmethod
    def _sanitize_locations(
        sanitizer: "_JulietFunctionSanitizer",
        source_location: Optional[CodeLocation],
        sink_location: Optional[CodeLocation],
        primary_location: Optional[CodeLocation],
    ) -> None:
        for location in (source_location, sink_location, primary_location):
            if location is None:
                continue
            location.code = sanitizer.sanitize_code(location.code)

    @staticmethod
    def _extract_method_body_from_preprocessed(
        case_input_dir: Path,
        dataset_relative_path: str,
        start_line: int,
        end_line: int,
        fallback_code: str,
    ) -> str:
        candidate = case_input_dir / Path(dataset_relative_path).name
        if not candidate.exists():
            return fallback_code
        lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
        if not lines or start_line <= 0:
            return fallback_code

        start = max(1, start_line)
        if end_line <= 0 or end_line < start:
            end = JoernStaticAnalyzer._estimate_method_end(lines, start)
        else:
            end = end_line
        end = min(len(lines), max(start, end))
        body = "\n".join(lines[start - 1 : end]).strip()
        return body or fallback_code

    @staticmethod
    def _estimate_method_end(lines: list[str], start_line: int) -> int:
        brace_depth = 0
        seen_open = False
        for index in range(start_line - 1, len(lines)):
            line = lines[index]
            brace_depth += line.count("{")
            if line.count("{") > 0:
                seen_open = True
            brace_depth -= line.count("}")
            if seen_open and brace_depth <= 0:
                return index + 1
        return len(lines)


class _JulietFunctionSanitizer:
    _BLOCK_COMMENT_PATTERN = re.compile(r"/\*.*?\*/", re.DOTALL)
    _LINE_COMMENT_PATTERN = re.compile(r"//.*?$", re.MULTILINE)
    _IDENTIFIER_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    _JULIET_IDENTIFIER_PATTERN = re.compile(r"\bCWE\d+[A-Za-z0-9_]*\b")

    def __init__(self) -> None:
        self._symbol_map: dict[str, str] = {}
        self._counter = 0

    def learn(self, chain_methods: list[str], method_defs: dict[str, _JoernMethodDef]) -> None:
        for method_name in chain_methods:
            for token in self._JULIET_IDENTIFIER_PATTERN.findall(method_name):
                self._register(token)
            method_def = method_defs.get(method_name)
            if method_def is None:
                continue
            for token in self._JULIET_IDENTIFIER_PATTERN.findall(method_def.code):
                self._register(token)

    def sanitize_method_name(self, method_name: str) -> str:
        return self._IDENTIFIER_PATTERN.sub(self._replace_identifier, method_name)

    def sanitize_code(self, code: str) -> str:
        if not code:
            return ""
        code = self._BLOCK_COMMENT_PATTERN.sub("", code)
        code = self._LINE_COMMENT_PATTERN.sub("", code)
        code = self._IDENTIFIER_PATTERN.sub(self._replace_identifier, code)
        lines = [line.rstrip() for line in code.splitlines()]
        lines = [line for line in lines if line.strip()]
        return "\n".join(lines).strip()

    def _replace_identifier(self, match: re.Match[str]) -> str:
        token = match.group(0)
        return self._symbol_map.get(token, token)

    def _register(self, token: str) -> None:
        if token in self._symbol_map:
            return
        self._counter += 1
        self._symbol_map[token] = f"func_{self._counter}"
