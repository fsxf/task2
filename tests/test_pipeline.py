from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from hybrid_vuln_audit.benchmark import enumerate_target_cases
from hybrid_vuln_audit.config import AppConfig
from hybrid_vuln_audit.static_analysis import JulietStaticAnalyzer


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dataset_root = ROOT / "benchmark_subset" / "testcases"
        self.config = AppConfig.from_env(dataset_root=self.dataset_root, results_dir=ROOT / "results")

    def test_enumeration_finds_60_cases(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        self.assertEqual(len(cases), 60)

    def test_static_analyzer_detects_cwe78(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("char_connect_socket_execl_51"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertIsNotNone(evidence.sink_location)
        self.assertEqual(evidence.sink_location.line, 71)

    def test_static_analyzer_detects_cwe259(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("w32_char_84"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertIsNotNone(evidence.source_location)
        self.assertEqual(evidence.source_location.line, 32)

    def test_static_analyzer_detects_constructor_destructor_flow(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("char_file_execl_83"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertEqual(evidence.source_location.line, 49)
        self.assertEqual(evidence.sink_location.line, 66)


if __name__ == "__main__":
    unittest.main()
