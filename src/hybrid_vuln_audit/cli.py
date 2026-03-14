from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .benchmark import enumerate_target_cases
from .config import AppConfig
from .llm import DeepSeekReviewer
from .models import AnalysisResult
from .reporting import write_reports
from .static_analysis import JulietStaticAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hybrid vulnerability audit pipeline for Juliet benchmark cases.")
    parser.add_argument("--dataset-root", type=Path, default=Path("benchmark_subset") / "testcases")
    parser.add_argument("--results-dir", type=Path, default=Path("results"))
    parser.add_argument("--offline", action="store_true", help="Disable online DeepSeek-R1 calls.")
    parser.add_argument("--limit", type=int, default=0, help="Optional debug limit.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = AppConfig.from_env(dataset_root=args.dataset_root, results_dir=args.results_dir)
    cases = enumerate_target_cases(config.dataset_root)
    if args.limit > 0:
        cases = cases[: args.limit]

    analyzer = JulietStaticAnalyzer(config)
    reviewer = DeepSeekReviewer(config, force_offline=args.offline)
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
            )
        )

    write_reports(results, config.results_dir)

    print(f"cases={len(results)}")
    print(f"results={config.results_dir}")
    print(f"mode={'offline-estimate' if args.offline or not config.deepseek_enabled else 'deepseek-r1'}")
    return 0
