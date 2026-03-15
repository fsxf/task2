from __future__ import annotations

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

        with tempfile.TemporaryDirectory(dir=str(case_temp_root)) as temp_dir:
            temp_path = Path(temp_dir)
            for file_path in self._select_case_files(context):
                shutil.copy2(str(file_path), str(temp_path / file_path.name))

            findings_path = temp_path / "findings.tsv"
            project_name = "hybrid-vuln-audit-{0}".format(uuid4().hex)
            self._run_joern(
                input_path=temp_path,
                findings_path=findings_path,
                cwe=context.cwe,
                analysis_scope=context.analysis_scope,
                project_name=project_name,
            )
            try:
                findings = self._parse_findings(findings_path, context, dataset_root)
                if not findings:
                    return StaticEvidence(
                        is_vulnerable=False,
                        confidence=0.60,
                        primary_location=None,
                        source_location=None,
                        sink_location=None,
                        source_snippet="",
                        sink_snippet="",
                        notes=[
                            "static backend: joern",
                            "joern returned no source or sink findings",
                            "flow chain: {0}".format(" -> ".join(context.flow_chain)),
                        ],
                    )
            finally:
                self._cleanup_project_workspace(project_name)

        source_location = self._pick_best_finding(findings, "SOURCE", context.analysis_scope)
        sink_location = self._pick_best_finding(findings, "SINK", context.analysis_scope)
        primary_location = sink_location if context.cwe == "CWE78" else source_location
        verdict = source_location is not None and sink_location is not None
        return StaticEvidence(
            is_vulnerable=verdict,
            confidence=0.99 if verdict else 0.70,
            primary_location=primary_location,
            source_location=source_location,
            sink_location=sink_location,
            source_snippet=self._render_window(context.source_file, source_location.line) if source_location else "",
            sink_snippet=self._render_window(context.sink_file, sink_location.line) if sink_location else "",
            notes=[
                "static backend: joern",
                "joern script: {0}".format(self._config.joern_script_path.name),
                "flow chain: {0}".format(" -> ".join(context.flow_chain)),
            ],
        )

    def _select_case_files(self, context: CaseContext) -> List[Path]:
        selected: List[Path] = []
        for file_path in context.group_files:
            name = file_path.name
            if file_path.suffix == ".h":
                selected.append(file_path)
                continue
            if file_path == context.root_file or file_path == context.source_file or file_path == context.sink_file:
                selected.append(file_path)
                continue
            if "_bad." in name:
                selected.append(file_path)
        unique = []
        seen = set()
        for item in selected:
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
        analysis_scope: str,
        project_name: str,
    ) -> None:
        command = self._build_command(
            input_path=input_path,
            findings_path=findings_path,
            cwe=cwe,
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

    def _pick_best_finding(self, findings: List[_JoernFinding], kind: str, analysis_scope: str) -> Optional[CodeLocation]:
        candidates = [finding for finding in findings if finding.kind == kind]
        if not candidates:
            return None
        scoped_candidates = [finding for finding in candidates if analysis_scope.lower() in finding.method_name.lower()]
        chosen = scoped_candidates[0] if scoped_candidates else candidates[0]
        return CodeLocation(path=chosen.path, line=chosen.line, code=chosen.code)

    @staticmethod
    def _render_window(file_path: Path, line_no: int) -> str:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(1, line_no - 3)
        end = min(len(lines), line_no + 3)
        return "\n".join("{0:>4}: {1}".format(index, lines[index - 1]) for index in range(start, end + 1))

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
