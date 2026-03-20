from __future__ import annotations

from pathlib import Path

from .config import AppConfig
from .joern_runner import JoernStaticAnalyzer
from .models import CaseContext, StaticEvidence


class JulietStaticAnalyzer:
    def __init__(self, config: AppConfig) -> None:
        self._joern_analyzer = JoernStaticAnalyzer(config)

    def analyze(self, context: CaseContext, dataset_root: Path) -> StaticEvidence:
        evidence = self._joern_analyzer.analyze(context, dataset_root)
        if evidence is None:
            raise RuntimeError("Joern analysis failed to produce findings for case: {0}".format(context.case_id))
        return evidence
