from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .benchmark import enumerate_target_cases
from .config import AppConfig
from .llm import DeepSeekReviewer
from .models import AnalysisResult
from .prompting import build_messages
from .reporting import write_reports
from .static_analysis import JulietStaticAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hybrid vulnerability audit pipeline for Juliet benchmark cases.")
    parser.add_argument("--dataset-root", type=Path, default=Path("benchmark_subset") / "testcases")
    parser.add_argument("--results-dir", type=Path, default=Path("results"))
    parser.add_argument("--limit", type=int, default=0, help="Optional debug limit.")
    parser.add_argument("--show-config", action="store_true", help="Print the current DeepSeek and Joern configuration.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = AppConfig.from_env(dataset_root=args.dataset_root, results_dir=args.results_dir)
    if args.show_config:
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
    reviewer = DeepSeekReviewer(config)
    results: list[AnalysisResult] = []
    prompt_dir = config.results_dir / "llm_prompts"
    prompt_dir.mkdir(parents=True, exist_ok=True)

    for context in cases:
        evidence = analyzer.analyze(context, config.dataset_root)
        messages = build_messages(context, evidence)
        _write_prompt_preview(prompt_dir / f"{context.case_id}.txt", messages)
        review = reviewer.review(context, evidence, prebuilt_messages=messages)
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
                prompt_tokens=review.prompt_tokens,
                completion_tokens=review.completion_tokens,
                total_tokens=review.total_tokens,
                reason=review.reason,
            )
        )

    write_reports(results, config.results_dir)
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


def _write_prompt_preview(target: Path, messages: tuple[str, str]) -> None:
    system_prompt, user_prompt = messages
    payload = "\n".join(
        [
            "[SYSTEM]",
            system_prompt.strip(),
            "",
            "[USER]",
            user_prompt.strip(),
            "",
        ]
    )
    target.write_text(payload, encoding="utf-8-sig")
