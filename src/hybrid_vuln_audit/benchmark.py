from __future__ import annotations

from pathlib import Path
import re
from dataclasses import dataclass
from typing import Optional

from .models import CaseContext


SUPPORTED_VARIANTS = {"51", "52", "53", "54", "61", "62", "81", "82", "83", "84"}

_CWE78_ROOT = re.compile(
    r"^(?P<case>CWE78_OS_Command_Injection__char_(?P<source>.+)_execl_(?P<variant>\d+))a\.(?P<ext>c|cpp)$"
)
_CWE259_ROOT = re.compile(
    r"^(?P<case>CWE259_Hard_Coded_Password__w32_char_(?P<variant>\d+))a\.(?P<ext>c|cpp)$"
)


@dataclass(frozen=True)
class _Resolution:
    source_file: Path
    sink_file: Path
    flow_chain: list[str]


def enumerate_target_cases(dataset_root: Path) -> list[CaseContext]:
    cases: list[CaseContext] = []
    for file_path in sorted(dataset_root.rglob("*")):
        if not file_path.is_file():
            continue
        parsed = _parse_root_case(file_path)
        if parsed is None:
            continue
        resolution = _resolve_bad_path(parsed["variant"], file_path, parsed["case"], parsed["ext"])
        group_files = sorted(file_path.parent.glob(f"{parsed['case']}*"), key=lambda item: item.name)
        cases.append(
            CaseContext(
                case_id=parsed["case"],
                cwe=parsed["cwe"],
                variant=parsed["variant"],
                source_kind=parsed["source_kind"],
                root_file=file_path,
                group_files=group_files,
                source_file=resolution.source_file,
                sink_file=resolution.sink_file,
                flow_chain=resolution.flow_chain,
                analysis_scope="bad",
            )
        )
    return cases


def _parse_root_case(file_path: Path) -> Optional[dict]:
    match = _CWE78_ROOT.match(file_path.name)
    if match and match.group("variant") in SUPPORTED_VARIANTS:
        return {
            "cwe": "CWE78",
            "case": match.group("case"),
            "variant": match.group("variant"),
            "ext": match.group("ext"),
            "source_kind": match.group("source"),
        }

    match = _CWE259_ROOT.match(file_path.name)
    if match and match.group("variant") in SUPPORTED_VARIANTS:
        return {
            "cwe": "CWE259",
            "case": match.group("case"),
            "variant": match.group("variant"),
            "ext": match.group("ext"),
            "source_kind": "w32_char",
        }

    return None


def _resolve_bad_path(variant: str, root_file: Path, case_name: str, ext: str) -> _Resolution:
    parent = root_file.parent

    if variant in {"51", "52", "53", "54"}:
        sink_suffix = {"51": "b", "52": "c", "53": "d", "54": "e"}[variant]
        sink_file = parent / f"{case_name}{sink_suffix}.{ext}"
        return _Resolution(source_file=root_file, sink_file=sink_file, flow_chain=[root_file.name, sink_file.name])

    if variant in {"61", "62"}:
        source_file = parent / f"{case_name}b.{ext}"
        return _Resolution(source_file=source_file, sink_file=root_file, flow_chain=[source_file.name, root_file.name])

    if variant in {"81", "82"}:
        sink_file = parent / f"{case_name}_bad.cpp"
        return _Resolution(source_file=root_file, sink_file=sink_file, flow_chain=[root_file.name, sink_file.name])

    if variant in {"83", "84"}:
        bad_file = parent / f"{case_name}_bad.cpp"
        return _Resolution(
            source_file=bad_file,
            sink_file=bad_file,
            flow_chain=[root_file.name, f"{bad_file.name}::constructor", f"{bad_file.name}::destructor"],
        )

    raise ValueError(f"Unsupported variant: {variant}")
