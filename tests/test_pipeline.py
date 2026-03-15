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
from hybrid_vuln_audit.good_paths import build_good_path_contexts
from hybrid_vuln_audit.static_analysis import JulietStaticAnalyzer


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dataset_root = ROOT / "benchmark_subset" / "testcases"
        self.config = AppConfig.from_env(dataset_root=self.dataset_root, results_dir=ROOT / "results")

    def test_enumeration_finds_20_cases(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        self.assertEqual(len(cases), 20)

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
        target = next(case for case in cases if case.case_id.endswith("char_connect_socket_execl_83"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertEqual(evidence.source_location.line, 90)
        self.assertEqual(evidence.sink_location.line, 127)

    def test_enumeration_builds_20_good_path_contexts(self) -> None:
        self.assertEqual(len(build_good_path_contexts(self.dataset_root)), 20)

    def test_all_good_paths_are_not_flagged(self) -> None:
        analyzer = JulietStaticAnalyzer(self.config)
        for context in build_good_path_contexts(self.dataset_root):
            with self.subTest(case_id=context.case_id):
                evidence = analyzer.analyze(context, self.dataset_root)
                self.assertFalse(evidence.is_vulnerable)
                self.assertIsNone(evidence.source_location)
                self.assertIsNotNone(evidence.sink_location)


if __name__ == "__main__":
    unittest.main()
