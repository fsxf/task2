from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import AnalysisResult


def write_reports(results: list[AnalysisResult], results_dir: Path) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    _write_json(results, results_dir / "analysis_results.json")
    _write_csv(results, results_dir / "analysis_results.csv")
    _write_summary(results, results_dir / "summary.md")


def _write_json(results: list[AnalysisResult], target: Path) -> None:
    target.write_text(
        json.dumps([result.to_dict() for result in results], ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )


def _write_csv(results: list[AnalysisResult], target: Path) -> None:
    fieldnames = [
        "case_id",
        "cwe",
        "variant",
        "root_file",
        "vulnerable",
        "expected_vulnerable",
        "correct",
        "primary_path",
        "primary_line",
        "source_path",
        "source_line",
        "sink_path",
        "sink_line",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "llm_mode",
        "llm_model",
        "reason",
    ]
    with target.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "case_id": result.case_id,
                    "cwe": result.cwe,
                    "variant": result.variant,
                    "root_file": result.root_file,
                    "vulnerable": result.vulnerable,
                    "expected_vulnerable": result.expected_vulnerable,
                    "correct": result.correct,
                    "primary_path": result.primary_location.path if result.primary_location else "",
                    "primary_line": result.primary_location.line if result.primary_location else "",
                    "source_path": result.source_location.path if result.source_location else "",
                    "source_line": result.source_location.line if result.source_location else "",
                    "sink_path": result.sink_location.path if result.sink_location else "",
                    "sink_line": result.sink_location.line if result.sink_location else "",
                    "prompt_tokens": result.prompt_tokens,
                    "completion_tokens": result.completion_tokens,
                    "total_tokens": result.total_tokens,
                    "llm_mode": result.llm_mode,
                    "llm_model": result.llm_model,
                    "reason": result.reason,
                }
            )


def _write_summary(results: list[AnalysisResult], target: Path) -> None:
    total = len(results)
    correct = sum(1 for result in results if result.correct)
    accuracy = (correct / total) if total else 0.0
    prompt_tokens = sum(result.prompt_tokens for result in results)
    completion_tokens = sum(result.completion_tokens for result in results)
    total_tokens = sum(result.total_tokens for result in results)

    lines = [
        "# 实验总结",
        "",
        f"- 总实例数: {total}",
        f"- 正确数: {correct}",
        f"- 准确率: {accuracy:.2%}",
        f"- Prompt Tokens: {prompt_tokens}",
        f"- Completion Tokens: {completion_tokens}",
        f"- Total Tokens: {total_tokens}",
        f"- 平均每例 Tokens: {(total_tokens / total) if total else 0:.2f}",
        "",
        "## 分 CWE 结果",
    ]
    for cwe in sorted({result.cwe for result in results}):
        subset = [result for result in results if result.cwe == cwe]
        lines.append(
            f"- {cwe}: {len(subset)} cases, accuracy={sum(1 for item in subset if item.correct) / len(subset):.2%}, "
            f"avg_tokens={sum(item.total_tokens for item in subset) / len(subset):.2f}"
        )

    target.write_text("\n".join(lines), encoding="utf-8-sig")
