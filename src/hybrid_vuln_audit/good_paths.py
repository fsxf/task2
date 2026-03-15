from __future__ import annotations

import json
from pathlib import Path

from .benchmark import enumerate_target_cases
from .models import CaseContext
from .static_analysis import JulietStaticAnalyzer


def build_good_path_contexts(dataset_root: Path) -> list[CaseContext]:
    contexts: list[CaseContext] = []
    for bad_case in enumerate_target_cases(dataset_root):
        root_file = bad_case.root_file
        source_file = bad_case.source_file
        sink_file = bad_case.sink_file
        flow_chain = list(bad_case.flow_chain)

        if bad_case.variant in {"81", "82"}:
            sink_file = bad_case.root_file.parent / f"{bad_case.case_id}_goodG2B.cpp"
            flow_chain = [bad_case.root_file.name, sink_file.name]
        elif bad_case.variant in {"83", "84"}:
            good_file = bad_case.root_file.parent / f"{bad_case.case_id}_goodG2B.cpp"
            source_file = good_file
            sink_file = good_file
            flow_chain = [bad_case.root_file.name, f"{good_file.name}::constructor", f"{good_file.name}::destructor"]

        contexts.append(
            CaseContext(
                case_id=f"{bad_case.case_id}_good_path",
                cwe=bad_case.cwe,
                variant=bad_case.variant,
                source_kind=bad_case.source_kind,
                root_file=root_file,
                group_files=bad_case.group_files,
                source_file=source_file,
                sink_file=sink_file,
                flow_chain=flow_chain,
                expected_vulnerable=False,
                analysis_scope="good",
            )
        )
    return contexts


def evaluate_good_paths(analyzer: JulietStaticAnalyzer, dataset_root: Path) -> list[dict]:
    results: list[dict] = []
    for context in build_good_path_contexts(dataset_root):
        evidence = analyzer.analyze(context, dataset_root)
        results.append(
            {
                "case_id": context.case_id,
                "cwe": context.cwe,
                "variant": context.variant,
                "analysis_scope": context.analysis_scope,
                "root_file": context.relative_root(dataset_root),
                "source_file": context.source_file.relative_to(dataset_root).as_posix(),
                "sink_file": context.sink_file.relative_to(dataset_root).as_posix(),
                "flow_chain": context.flow_chain,
                "vulnerable": evidence.is_vulnerable,
                "expected_vulnerable": context.expected_vulnerable,
                "correct": evidence.is_vulnerable == context.expected_vulnerable,
                "primary_location": evidence.primary_location.to_dict() if evidence.primary_location else None,
                "source_location": evidence.source_location.to_dict() if evidence.source_location else None,
                "sink_location": evidence.sink_location.to_dict() if evidence.sink_location else None,
                "static_confidence": evidence.confidence,
                "notes": evidence.notes,
            }
        )
    return results


def write_good_path_report(results: list[dict], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8-sig")
