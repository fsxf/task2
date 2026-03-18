from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import List, Optional
from uuid import uuid4

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


class JoernStaticAnalyzer:
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

        if self._config.joern_keep_projects:
            temp_path = self._prepare_kept_case_directory(case_temp_root, project_name, context)
            try:
                findings = self._analyze_with_joern(temp_path, context, dataset_root, project_name)
            except RuntimeError as exc:
                if not self._should_retry_with_fresh_project(exc):
                    raise
                project_name = "{0}-{1}".format(project_name, uuid4().hex[:8])
                temp_path = self._prepare_kept_case_directory(case_temp_root, project_name, context)
                findings = self._analyze_with_joern(temp_path, context, dataset_root, project_name)
        else:
            with tempfile.TemporaryDirectory(dir=str(case_temp_root)) as temp_dir:
                temp_path = Path(temp_dir)
                for file_path in self._select_case_files(context):
                    shutil.copy2(str(file_path), str(temp_path / file_path.name))
                findings = self._analyze_with_joern(temp_path, context, dataset_root, project_name)

        source_finding = self._pick_best_finding(findings, "SOURCE", context.analysis_scope)
        sink_finding = self._pick_best_finding(findings, "SINK", context.analysis_scope)
        source_location = self._to_location(source_finding)
        sink_location = self._to_location(sink_finding)
        primary_location = sink_location if context.cwe == "CWE78" else source_location
        verdict = source_location is not None and sink_location is not None
        flow_evidence = self._build_flow_evidence(findings, source_finding, sink_finding, context)
        notes = [
            "static backend: joern",
            "joern script: {0}".format(self._config.joern_script_path.name),
            "joern import scope: full case file group",
            "flow chain: {0}".format(" -> ".join(context.flow_chain)),
        ]
        if flow_evidence:
            notes.append("joern flow evidence items: {0}".format(len(flow_evidence)))
        if self._config.joern_keep_projects:
            notes.extend(
                [
                    "joern project: {0}".format(project_name),
                    "joern workspace root: {0}".format(self._config.joern_workspace_root),
                    "joern case input root: {0}".format(self._config.joern_case_temp_root),
                ]
            )
        return StaticEvidence(
            is_vulnerable=verdict,
            confidence=0.99 if verdict else 0.70,
            primary_location=primary_location,
            source_location=source_location,
            sink_location=sink_location,
            source_snippet=self._render_window(self._resolve_group_file(context, source_location.path), source_location.line) if source_location else "",
            sink_snippet=self._render_window(self._resolve_group_file(context, sink_location.path), sink_location.line) if sink_location else "",
            notes=notes,
            flow_evidence=flow_evidence,
        )

    def _analyze_with_joern(
        self,
        temp_path: Path,
        context: CaseContext,
        dataset_root: Path,
        project_name: str,
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
        try:
            findings = self._parse_findings(findings_path, context, dataset_root)
            if not findings:
                return []
            return findings
        finally:
            if not self._config.joern_keep_projects:
                self._cleanup_project_workspace(project_name)

    def _select_case_files(self, context: CaseContext) -> List[Path]:
        # Import the full Juliet case group so Joern sees the complete case-level structure.
        unique = []
        seen = set()
        for item in context.group_files:
            key = str(item.resolve())
            if key not in seen:
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
        if self._config.joern_keep_projects:
            case_name = self._sanitize_name(context.case_id)
            scope_name = self._sanitize_name(context.analysis_scope)
            return "hybrid-vuln-audit-{0}-{1}".format(case_name, scope_name)
        return "hybrid-vuln-audit-{0}".format(uuid4().hex)

    def _prepare_kept_case_directory(self, case_temp_root: Path, project_name: str, context: CaseContext) -> Path:
        case_dir = case_temp_root / project_name
        if case_dir.exists():
            shutil.rmtree(str(case_dir), ignore_errors=True)
        case_dir.mkdir(parents=True, exist_ok=True)
        for file_path in self._select_case_files(context):
            shutil.copy2(str(file_path), str(case_dir / file_path.name))
        return case_dir

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

    def _parse_findings(self, findings_path: Path, context: CaseContext, dataset_root: Path) -> List[_JoernFinding]:
        if not findings_path.exists():
            return []
        rows: List[_JoernFinding] = []
        for raw_line in findings_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = raw_line.split("\t", 5)
            if len(parts) != 6:
                continue
            kind, relative_path, line, call_name, method_name, code = parts
            mapped_path = self._map_temp_path_to_dataset(relative_path, context, dataset_root)
            if mapped_path is None and kind == "DATAFLOW":
                mapped_path = context.root_file.relative_to(dataset_root).as_posix()
            if mapped_path is None:
                continue
            rows.append(
                _JoernFinding(
                    kind=kind,
                    path=mapped_path,
                    line=int(line),
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
    def _render_window(file_path: Path, line_no: int) -> str:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(1, line_no - 3)
        end = min(len(lines), line_no + 3)
        return "\n".join("{0:>4}: {1}".format(index, lines[index - 1]) for index in range(start, end + 1))

    def _build_flow_evidence(
        self,
        findings: List[_JoernFinding],
        source_finding: Optional[_JoernFinding],
        sink_finding: Optional[_JoernFinding],
        context: CaseContext,
    ) -> List[str]:
        evidence: List[str] = []
        if source_finding is not None:
            evidence.append("joern source method: {0}".format(self._friendly_method_name(source_finding.method_name)))
        if sink_finding is not None:
            evidence.append("joern sink method: {0}".format(self._friendly_method_name(sink_finding.method_name)))

        dataflow_evidence = self._extract_dataflow_evidence(findings)
        if dataflow_evidence:
            evidence.extend(dataflow_evidence)
        else:
            evidence.append("joern dataflow path: unavailable for this case")

        if source_finding is None or sink_finding is None:
            return evidence

        if source_finding.method_name == sink_finding.method_name:
            evidence.append(
                "joern same-method evidence: source and sink both appear in {0}".format(
                    self._friendly_method_name(source_finding.method_name)
                )
            )
            return evidence

        call_edges = self._extract_call_edges(findings)
        if not call_edges:
            evidence.append("joern call path: no internal call edges recovered for this case")
            return evidence

        directed_path = self._find_method_path(call_edges, source_finding.method_name, sink_finding.method_name, directed=True)
        if directed_path:
            evidence.extend(self._render_path_evidence("joern call path", directed_path))
            return evidence

        reverse_path = self._find_method_path(call_edges, sink_finding.method_name, source_finding.method_name, directed=True)
        if reverse_path:
            evidence.extend(self._render_path_evidence("joern reverse call path", reverse_path))
            return evidence

        structural_path = self._find_method_path(call_edges, source_finding.method_name, sink_finding.method_name, directed=False)
        if structural_path:
            evidence.extend(self._render_path_evidence("joern structural path", structural_path))
            return evidence

        evidence.append("joern call path: no path recovered from internal call edges")
        evidence.append("benchmark flow chain: {0}".format(" -> ".join(context.flow_chain)))
        return evidence

    @staticmethod
    def _extract_dataflow_evidence(findings: List[_JoernFinding]) -> List[str]:
        rendered: List[str] = []
        seen = set()
        for finding in findings:
            if finding.kind != "DATAFLOW":
                continue
            text = "joern dataflow path ({0}): {1}".format(finding.call_name, finding.code)
            if text in seen:
                continue
            seen.add(text)
            rendered.append(text)
        return rendered

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

    def _render_path_evidence(self, label: str, path: List[tuple[_JoernCallEdge, bool]]) -> List[str]:
        if not path:
            return []

        methods = [path[0][0].caller if path[0][1] else path[0][0].callee]
        for edge, is_forward in path:
            methods.append(edge.callee if is_forward else edge.caller)

        evidence = [
            "{0}: {1}".format(
                label,
                " -> ".join(self._friendly_method_name(method_name) for method_name in methods),
            )
        ]
        for edge, is_forward in path:
            arrow = "->" if is_forward else "<-"
            evidence.append(
                "joern call edge: {0}:{1} {2} {3} {4} | {5}".format(
                    edge.path,
                    edge.line,
                    self._friendly_method_name(edge.caller),
                    arrow,
                    self._friendly_method_name(edge.callee),
                    edge.code,
                )
            )
        return evidence

    def _cleanup_project_workspace(self, project_name: str) -> None:
        workspace_dir = self._config.joern_workspace_root.resolve() / "workspace"
        project_dir = workspace_dir / project_name
        if project_dir.exists():
            shutil.rmtree(str(project_dir), ignore_errors=True)
        if workspace_dir.exists():
            try:
                next(workspace_dir.iterdir())
            except StopIteration:
                workspace_dir.rmdir()

    @staticmethod
    def _sanitize_name(value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value)

    @staticmethod
    def _resolve_group_file(context: CaseContext, relative_path: str) -> Path:
        report_name = Path(relative_path).name
        for candidate in context.group_files:
            if candidate.name == report_name:
                return candidate
        raise FileNotFoundError("Unable to resolve Joern finding path: {0}".format(relative_path))

    @staticmethod
    def _friendly_method_name(method_name: str) -> str:
        normalized = method_name.strip()
        if not normalized:
            return "<unknown>"
        return normalized.split(":", 1)[0]

    @staticmethod
    def _should_retry_with_fresh_project(exc: RuntimeError) -> bool:
        message = str(exc).lower()
        return "already exists" in message or "filesystemexception" in message or "进程无法访问" in message
