from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class AppConfig:
    dataset_root: Path
    results_dir: Path
    deepseek_base_url: str
    deepseek_model: str
    deepseek_api_key: Optional[str]
    deepseek_timeout_seconds: int
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
        return cls(
            dataset_root=(dataset_root or Path("benchmark_subset") / "testcases").resolve(),
            results_dir=(results_dir or Path("results")).resolve(),
            deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1").rstrip("/"),
            deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-reasoner"),
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY"),
            deepseek_timeout_seconds=int(os.getenv("DEEPSEEK_TIMEOUT_SECONDS", "60")),
        )
