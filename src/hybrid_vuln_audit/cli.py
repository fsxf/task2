from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .benchmark import enumerate_target_cases
from .config import AppConfig
from .good_paths import evaluate_good_paths, write_good_path_report
from .llm import DeepSeekReviewer
from .models import AnalysisResult
from .reporting import write_reports
from .static_analysis import JulietStaticAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hybrid vulnerability audit pipeline for Juliet benchmark cases.")
    parser.add_argument("--dataset-root", type=Path, default=Path("benchmark_subset") / "testcases")
    parser.add_argument("--results-dir", type=Path, default=Path("results"))
    parser.add_argument("--limit", type=int, default=0, help="Optional debug limit.")
    parser.add_argument("--show-config", action="store_true", help="Print the current DeepSeek and Joern configuration.")
    parser.add_argument(
        "--good-paths-only",
        action="store_true",
        help="Only export static-analysis results for the Good execution paths.",
    )
    parser.add_argument(
        "--export-good-paths",
        action="store_true",
        help="Export results/good_sample_results.json after the main benchmark run.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = AppConfig.from_env(dataset_root=args.dataset_root, results_dir=args.results_dir)
    if args.show_config:
        print("static_backend={0}".format(config.static_analysis_backend))
        print("java_home={0}".format(config.java_home or "NOT_SET"))
        print("joern_cli_path={0}".format(config.joern_cli_path or "AUTO_DETECT"))
        print("joern_script_path={0}".format(config.joern_script_path))
        print("joern_workspace_root={0}".format(config.joern_workspace_root))
        print("joern_case_temp_root={0}".format(config.joern_case_temp_root))
        print("joern_keep_projects={0}".format(config.joern_keep_projects))
        print("deepseek_base_url={0}".format(config.deepseek_base_url))
        print("deepseek_model={0}".format(config.deepseek_model))
        print("deepseek_api_key={0}".format(_mask_secret(config.deepseek_api_key)))
        return 0

    cases = enumerate_target_cases(config.dataset_root)
    if args.limit > 0:
        cases = cases[: args.limit]

    analyzer = JulietStaticAnalyzer(config)
    if args.good_paths_only:
        good_path_results = evaluate_good_paths(analyzer, config.dataset_root)
        target = config.results_dir / "good_sample_results.json"
        write_good_path_report(good_path_results, target)
        print("good_path_cases={0}".format(len(good_path_results)))
        print("good_path_results={0}".format(target))
        return 0

    reviewer = DeepSeekReviewer(config)
    results: list[AnalysisResult] = []

    for context in cases:
        evidence = analyzer.analyze(context, config.dataset_root)
        review = reviewer.review(context, evidence)
        results.append(
            AnalysisResult(
                case_id=context.case_id,
                cwe=context.cwe,
                variant=context.variant,
                root_file=context.relative_root(config.dataset_root),
                vulnerable=review.verdict,
                expected_vulnerable=context.expected_vulnerable,
                correct=review.verdict == context.expected_vulnerable,
                primary_location=evidence.primary_location,
                source_location=evidence.source_location,
                sink_location=evidence.sink_location,
                flow_chain=context.flow_chain,
                prompt_tokens=review.prompt_tokens,
                completion_tokens=review.completion_tokens,
                total_tokens=review.total_tokens,
                llm_mode=review.mode,
                llm_model=review.model,
                reason=review.reason,
                static_confidence=evidence.confidence,
                review_confidence=review.confidence,
                notes=evidence.notes,
                flow_evidence=evidence.flow_evidence,
            )
        )

    write_reports(results, config.results_dir)
    if args.export_good_paths:
        write_good_path_report(evaluate_good_paths(analyzer, config.dataset_root), config.results_dir / "good_sample_results.json")

    print(f"cases={len(results)}")
    print(f"results={config.results_dir}")
    print("mode=deepseek-r1")
    return 0


def _mask_secret(value: Optional[str]) -> str:
    if not value:
        return "NOT_SET"
    if len(value) <= 8:
        return "*" * len(value)
    return "{0}...{1}".format(value[:4], value[-4:])
