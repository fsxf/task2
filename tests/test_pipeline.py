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
from hybrid_vuln_audit.joern_runner import JoernStaticAnalyzer, _JoernCallEdge, _JoernFinding
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
        self.assertGreater(evidence.sink_location.line, 0)
        self.assertTrue(any(item.startswith("joern call path:") for item in evidence.flow_evidence))
        self.assertGreaterEqual(len(evidence.function_evidence), 2)
        joined_bodies = "\n".join(evidence.function_evidence)
        self.assertIn("func_", joined_bodies)
        self.assertIn("_execl", joined_bodies)

    def test_static_analyzer_detects_cwe259(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("w32_char_84"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertIsNotNone(evidence.source_location)
        self.assertGreater(evidence.source_location.line, 0)
        self.assertTrue(any(item.startswith("joern source method:") for item in evidence.flow_evidence))
        self.assertGreaterEqual(len(evidence.function_evidence), 1)

    def test_static_analyzer_detects_constructor_destructor_flow(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("char_connect_socket_execl_83"))
        evidence = JulietStaticAnalyzer(self.config).analyze(target, self.dataset_root)
        self.assertTrue(evidence.is_vulnerable)
        self.assertGreater(evidence.source_location.line, 0)
        self.assertGreater(evidence.sink_location.line, 0)

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
        self.assertIn("func_", joined)
        self.assertNotIn("dataflow", joined.lower())

    def test_joern_project_name_uses_case_id(self) -> None:
        cases = enumerate_target_cases(self.dataset_root)
        target = next(case for case in cases if case.case_id.endswith("char_connect_socket_execl_54"))
        project_name = JoernStaticAnalyzer(self.config)._build_project_name(target)
        self.assertEqual(project_name, target.case_id)

    def test_source_plus_one_adds_direct_caller_only(self) -> None:
        analyzer = JoernStaticAnalyzer(self.config)
        source = _JoernFinding(
            kind="SOURCE",
            path="CWE78/example.c",
            line=10,
            call_name="recv",
            method_name="pkg.source",
            code="recv(sock, buf, 100, 0)",
        )
        edges = [
            _JoernCallEdge(path="a.c", line=1, caller="pkg.entry", callee="pkg.source", code="pkg.source(data)"),
            _JoernCallEdge(path="a.c", line=2, caller="pkg.source", callee="pkg.sink", code="pkg.sink(data)"),
            _JoernCallEdge(path="a.c", line=3, caller="pkg.other", callee="pkg.source", code="pkg.source(other)"),
            _JoernCallEdge(path="a.c", line=4, caller="pkg.entry", callee="pkg.source", code="pkg.source(data)"),
        ]

        expanded = analyzer._expand_chain_with_source_plus_one(["pkg.source", "pkg.sink"], edges, source)
        self.assertEqual(expanded, ["pkg.entry", "pkg.other", "pkg.source", "pkg.sink"])

    def test_prompt_contains_only_function_bodies(self) -> None:
        context = CaseContext(
            case_id="CWE259_Hard_Coded_Password__w32_char_54",
            cwe="CWE259",
            variant="54",
            source_kind="hardcoded_password",
            root_file=self.dataset_root / "CWE259" / "example.c",
            group_files=[],
            source_file=self.dataset_root / "CWE259" / "example.c",
            sink_file=self.dataset_root / "CWE259" / "example_sink.c",
            flow_chain=["a.c", "b.c"],
            expected_vulnerable=True,
            analysis_scope="bad",
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
                "joern call path: func_1 -> func_2",
                "benchmark flow chain: a.c -> b.c",
            ],
            function_evidence=[
                "Function 1: func_1\nvoid func_1() { recv(sock, buf, 100, 0); func_2(buf); }",
                "Function 2: func_2\nvoid func_2(char *password) { LogonUserA(u, d, password, 0, 0, &token); }",
            ],
        )
        system_prompt, user_prompt = build_messages(context, evidence)
        self.assertNotIn("confidence", system_prompt.lower())
        self.assertIn("function bodies", user_prompt.lower())
        self.assertIn("Function 1: func_1", user_prompt)
        self.assertIn("LogonUserA", user_prompt)
        self.assertNotIn("Case:", user_prompt)
        self.assertNotIn("CWE:", user_prompt)
        self.assertNotIn("Candidate ", user_prompt)
        self.assertNotIn("Call-chain evidence", user_prompt)
        self.assertNotIn("CWE259/example_bad.c", user_prompt)


if __name__ == "__main__":
    unittest.main()
