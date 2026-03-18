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
from hybrid_vuln_audit.joern_runner import JoernStaticAnalyzer
from hybrid_vuln_audit.models import CaseContext, CodeLocation, StaticEvidence
from hybrid_vuln_audit.prompting import build_messages
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
        self.assertTrue(any(item.startswith("joern call path:") for item in evidence.flow_evidence))
        self.assertTrue(any(item.startswith("joern dataflow path") for item in evidence.flow_evidence))

    def test_static_analyzer_detects_cwe259(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("w32_char_84"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertIsNotNone(evidence.source_location)
        self.assertEqual(evidence.source_location.line, 32)
        self.assertTrue(any(item.startswith("joern source method:") for item in evidence.flow_evidence))

    def test_static_analyzer_detects_constructor_destructor_flow(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("char_connect_socket_execl_83"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertEqual(evidence.source_location.line, 90)
        self.assertEqual(evidence.sink_location.line, 127)

    def test_enumeration_builds_20_good_path_contexts(self) -> None:
        self.assertEqual(len(build_good_path_contexts(self.dataset_root)), 20)

    def test_joern_imports_full_group_for_chain_variant(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("char_connect_socket_execl_54"))
        selected = JoernStaticAnalyzer(self.config)._select_case_files(target)
        self.assertEqual(
            [item.name for item in selected],
            [item.name for item in target.group_files],
        )

    def test_joern_emits_chain_evidence_for_variant_54(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("char_connect_socket_execl_54"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        joined = "\n".join(evidence.flow_evidence)
        self.assertIn("joern call path:", joined)
        self.assertIn("joern dataflow path", joined)
        self.assertIn("CWE78_OS_Command_Injection__char_connect_socket_execl_54_bad", joined)
        self.assertIn("CWE78_OS_Command_Injection__char_connect_socket_execl_54e_badSink", joined)

    def test_joern_emits_dataflow_for_cwe259_variant_54(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("w32_char_54"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        joined = "\n".join(evidence.flow_evidence)
        self.assertIn("joern dataflow path", joined)
        self.assertIn("IDENTIFIER | line 37 | password", joined)
        self.assertIn("IDENTIFIER | line 40 | password", joined)

    def test_all_good_paths_are_not_flagged(self) -> None:
        analyzer = JulietStaticAnalyzer(self.config)
        for context in build_good_path_contexts(self.dataset_root):
            with self.subTest(case_id=context.case_id):
                evidence = analyzer.analyze(context, self.dataset_root)
                self.assertFalse(evidence.is_vulnerable)
                self.assertIsNone(evidence.source_location)
                self.assertIsNotNone(evidence.sink_location)

    def test_prompt_hides_static_labels_and_dataset_answers(self) -> None:
        context = CaseContext(
            case_id="CWE259_Hard_Coded_Password__w32_char_54_good_path",
            cwe="CWE259",
            variant="54",
            source_kind="hardcoded_password",
            root_file=self.dataset_root / "CWE259" / "example.c",
            group_files=[],
            source_file=self.dataset_root / "CWE259" / "example.c",
            sink_file=self.dataset_root / "CWE259" / "example_sink.c",
            flow_chain=["a.c", "b.c"],
            expected_vulnerable=False,
            analysis_scope="good",
        )
        evidence = StaticEvidence(
            is_vulnerable=True,
            confidence=0.99,
            primary_location=CodeLocation(
                path="CWE259/example_bad.c",
                line=40,
                code="CWE259_Hard_Coded_Password__w32_char_54_badSink(password);",
            ),
            source_location=CodeLocation(
                path="CWE259/example_bad.c",
                line=32,
                code="strcpy(password, PASSWORD); /* FLAW: hardcoded secret */",
            ),
            sink_location=CodeLocation(
                path="CWE259/example_bad.c",
                line=40,
                code="LogonUserA(username, domain, password, ...);",
            ),
            source_snippet=(
                "  30: // FLAW: do not hardcode credentials\n"
                "  31: helper = CWE259_Hard_Coded_Password__w32_char_54_bad();\n"
                "  32: strcpy(password, PASSWORD);\n"
            ),
            sink_snippet=(
                "  38: data = goodG2BSource();\n"
                "  39: password = badSource();\n"
                "  40: LogonUserA(username, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token);\n"
            ),
            notes=[
                "static backend: joern",
                "flow chain: a.c -> b.c",
                "joern project: hidden-project",
            ],
            flow_evidence=[
                "joern call path: CWE259_Hard_Coded_Password__w32_char_54_bad -> CWE259_Hard_Coded_Password__w32_char_54_badSink",
                "benchmark flow chain: a.c -> b.c",
            ],
        )
        system_prompt, user_prompt = build_messages(context, evidence)
        self.assertNotIn("Judge only the BAD path", system_prompt)
        self.assertNotIn("Static verdict", user_prompt)
        self.assertNotIn("Static confidence", user_prompt)
        self.assertNotIn("flow chain:", user_prompt.lower())
        self.assertNotIn("benchmark flow chain", user_prompt.lower())
        self.assertNotIn("joern project:", user_prompt.lower())
        self.assertNotIn("good_path", user_prompt)
        self.assertNotIn("badSink", user_prompt)
        self.assertNotIn("goodG2BSource", user_prompt)
        self.assertNotIn("FLAW", user_prompt)
        self.assertIn("symbol_", user_prompt)


if __name__ == "__main__":
    unittest.main()
