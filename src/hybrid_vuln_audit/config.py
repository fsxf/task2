from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class AppConfig:
    project_root: Path
    dataset_root: Path
    results_dir: Path
    deepseek_base_url: str
    deepseek_model: str
    deepseek_api_key: Optional[str]
    deepseek_timeout_seconds: int
    static_analysis_backend: str
    java_home: Optional[Path]
    joern_cli_path: Optional[Path]
    joern_script_path: Path
    joern_workspace_root: Path
    joern_case_temp_root: Path
    prompt_window_radius: int = 3

    @property
    def deepseek_enabled(self) -> bool:
        return bool(self.deepseek_api_key)

    @classmethod
    def from_env(
        cls,
        dataset_root: Optional[Path] = None,
        results_dir: Optional[Path] = None,
    ) -> "AppConfig":
        project_root = Path.cwd().resolve()
        file_config = _load_runtime_config(project_root)

        return cls(
            project_root=project_root,
            dataset_root=(dataset_root or Path("benchmark_subset") / "testcases").resolve(),
            results_dir=(results_dir or Path("results")).resolve(),
            deepseek_base_url=_get_config_value(file_config, "deepseek_base_url", "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1").rstrip("/"),
            deepseek_model=_get_config_value(file_config, "deepseek_model", "DEEPSEEK_MODEL", "deepseek-reasoner"),
            deepseek_api_key=_normalize_optional_string(_get_config_value(file_config, "deepseek_api_key", "DEEPSEEK_API_KEY", "")),
            deepseek_timeout_seconds=int(_get_config_value(file_config, "deepseek_timeout_seconds", "DEEPSEEK_TIMEOUT_SECONDS", "180")),
            static_analysis_backend=_get_config_value(file_config, "static_analysis_backend", "STATIC_ANALYSIS_BACKEND", "joern").strip().lower(),
            java_home=_normalize_optional_path(project_root, _get_config_value(file_config, "java_home", "JAVA_HOME", "")),
            joern_cli_path=_normalize_optional_path(project_root, _get_config_value(file_config, "joern_cli_path", "JOERN_CLI_PATH", "")),
            joern_script_path=_normalize_path(project_root, _get_config_value(file_config, "joern_script_path", "JOERN_SCRIPT_PATH", "joern_scripts/find_case_findings.sc")),
            joern_workspace_root=_normalize_path(
                project_root,
                _get_config_value(
                    file_config,
                    "joern_workspace_root",
                    "JOERN_WORKSPACE_ROOT",
                    _default_temp_root("joern_runtime"),
                ),
            ),
            joern_case_temp_root=_normalize_path(
                project_root,
                _get_config_value(
                    file_config,
                    "joern_case_temp_root",
                    "JOERN_CASE_TEMP_ROOT",
                    _default_temp_root("joern_case_tmp"),
                ),
            ),
        )


def _load_runtime_config(project_root: Path) -> Dict[str, object]:
    config_path = project_root / "config" / "runtime_config.local.json"
    if not config_path.exists():
        return {}
    return json.loads(config_path.read_text(encoding="utf-8-sig"))


def _get_config_value(file_config: Dict[str, object], file_key: str, env_key: str, default: str) -> str:
    env_value = os.getenv(env_key)
    if env_value not in (None, ""):
        return env_value
    file_value = file_config.get(file_key, default)
    return str(file_value)


def _normalize_optional_string(value: str) -> Optional[str]:
    normalized = value.strip()
    if not normalized or normalized == "PASTE_YOUR_DEEPSEEK_API_KEY_HERE":
        return None
    return normalized


def _normalize_path(project_root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = (project_root / path).resolve()
    return path


def _normalize_optional_path(project_root: Path, value: str) -> Optional[Path]:
    normalized = value.strip()
    if not normalized or normalized.upper() == "AUTO_DETECT":
        return None
    return _normalize_path(project_root, normalized)


def _default_temp_root(name: str) -> str:
    return str((Path(tempfile.gettempdir()) / "hybrid_vuln_audit" / name).resolve())
