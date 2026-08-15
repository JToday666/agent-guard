#!/usr/bin/env python
"""Aggregate V21-08 shadow divergence from policy_evaluation audit records.

T7 离线分析工具（benchmark/工具档）：只读消费审计 ``evidence.decision_v21``
信封（``contract_freeze.yaml`` L84 ``v21_evidence_location``），按
``11_决策记录_V21-08前置.md`` D2 受控词表聚合 legacy × v21 九宫格矩阵、
降级类目分布与完整方案 §14（L3173-3177）三个分析组合的 case 列表，为
V21-10 pre-enable gate 的"shadow divergence 已解释"提供数据源。

解析口径（先经夹具探针验证后冻结）：``decision_v21`` 信封经 guard-api
``sanitize_audit_event``（§21.1/§21.2 redaction + MAX_NESTING_DEPTH=6
bounded projection）后，``DecisionEvidenceV21`` 的全部浅层标量字段存活：
``divergence_category`` / ``legacy_decision`` / ``v21_fast_disposition`` /
``mode`` / ``state_version`` / ``assessment_id`` / ``final_decision``。
本脚本只依赖这些存活字段做聚合；深层容器（coverage 嵌套、refs 对象等）
可能被收敛为 "..."，一律不作为聚合依据。

只读约束：不写库、不改契约、不接 Dashboard、不新增依赖。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "packages" / "agentguard-core"
API_PATH = ROOT / "apps" / "guard-api"
for import_path in (ROOT, CORE_PATH, API_PATH):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from agentguard_core.decisions.divergence import (  # noqa: E402
    DEGRADED_COMPONENT_FAILURE,
    DEGRADED_NO_SNAPSHOT,
    DIVERGENCE_GRID,
    DIVERGENCE_VOCABULARY,
)

#: legacy 决策轴（九宫格行序）。
LEGACY_DECISIONS = ("allow", "ask", "deny")

#: v21 FastDisposition 轴（九宫格列序）。
V21_DISPOSITIONS = ("CLEAR_ALLOW", "DEFER", "CLEAR_DENY")

#: §14（L3173-3177）三个分析组合 → D2 受控词表类目。
SECTION_14_COMBINATIONS = (
    ("legacy allow / v21 deny", "legacy_allow__v21_clear_deny"),
    ("legacy ask / v21 allow", "legacy_ask__v21_clear_allow"),
    ("legacy deny / v21 defer", "legacy_deny__v21_defer"),
)

#: 聚合所依赖的存活浅层字段（探针验证口径；缺失任一即计为 malformed）。
REQUIRED_PAYLOAD_FIELDS = (
    "divergence_category",
    "legacy_decision",
    "v21_fast_disposition",
)

#: 无信封跳过类别。
SKIP_NO_ENVELOPE = "no_envelope"
SKIP_NON_POLICY_EVALUATION = "non_policy_evaluation"
SKIP_MALFORMED = "malformed_envelope"


def load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    """读入 JSONL 审计记录夹具（每行一个 AuditEvent JSON dump）。"""

    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} must contain an object")
            records.append(value)
    return records


def load_postgres_records(database_url: str, *, limit: int) -> list[dict[str, Any]]:
    """经既有存储层有界读取接口取回 policy_evaluation 审计记录。

    只读语义：``read_audit_events_bounded``（契约 §5.2/§6.1，上界取当前
    链头），record_type 过滤到 policy_evaluation；测试库安全断言沿用
    ``tests/support/postgres.py`` 口径。
    """

    from tests.support.postgres import assert_safe_test_database_url
    from guard_api.storage.postgres import PostgresControlPlaneStore
    from guard_api.storage.base import AuditWindowQuery

    safe_url = assert_safe_test_database_url(database_url)
    store = PostgresControlPlaneStore(safe_url)
    events = store.read_audit_events_bounded(
        AuditWindowQuery(record_type="policy_evaluation", limit=limit)
    )
    return [event.model_dump(mode="json") for event in events]


def _payload_of(record: dict[str, Any]) -> dict[str, Any] | None:
    """提取 ``evidence.decision_v21.payload``；无信封返回 None。"""

    evidence = record.get("evidence")
    if not isinstance(evidence, dict):
        return None
    envelope = evidence.get("decision_v21")
    if not isinstance(envelope, dict):
        return None
    payload = envelope.get("payload")
    return payload if isinstance(payload, dict) else None


def _case_ref(record: dict[str, Any]) -> dict[str, Any]:
    """case 定位：event_id 取 ``links.event_id``（policy_evaluation 口径），
    trace_id 取记录顶层；缺失时确定性占位 ``<missing>``。"""

    links = record.get("links")
    event_id = links.get("event_id") if isinstance(links, dict) else None
    trace_id = record.get("trace_id")
    return {
        "event_id": event_id if isinstance(event_id, str) and event_id else "<missing>",
        "trace_id": trace_id if isinstance(trace_id, str) and trace_id else "<missing>",
    }


def aggregate_records(
    records: Iterable[dict[str, Any]], *, case_limit: int
) -> dict[str, Any]:
    """按 D2 受控词表聚合审计记录（纯函数，确定性）。"""

    matrix: dict[str, dict[str, int]] = {
        legacy: {disposition: 0 for disposition in V21_DISPOSITIONS}
        for legacy in LEGACY_DECISIONS
    }
    categories: Counter[str] = Counter()
    degraded: Counter[str] = Counter()
    modes: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    section_14_cases: dict[str, list[dict[str, Any]]] = {
        category: [] for _, category in SECTION_14_COMBINATIONS
    }
    anomalies: list[dict[str, Any]] = []
    envelope_count = 0
    total = 0

    for record in records:
        total += 1
        record_type = record.get("record_type")
        if record_type is not None and record_type != "policy_evaluation":
            skipped[SKIP_NON_POLICY_EVALUATION] += 1
            continue
        payload = _payload_of(record)
        if payload is None:
            skipped[SKIP_NO_ENVELOPE] += 1
            continue
        envelope_count += 1
        case = _case_ref(record)
        assessment_id = payload.get("assessment_id")
        case["assessment_id"] = (
            assessment_id if isinstance(assessment_id, str) else "<missing>"
        )

        missing = [
            field
            for field in REQUIRED_PAYLOAD_FIELDS
            if field not in payload
            or not isinstance(payload[field], (str, type(None)))
            or (field != "divergence_category" and payload[field] is None)
        ]
        if missing:
            skipped[SKIP_MALFORMED] += 1
            envelope_count -= 1
            anomalies.append({"kind": "missing_field", "fields": missing, **case})
            continue

        legacy = str(payload["legacy_decision"])
        disposition = str(payload["v21_fast_disposition"])
        raw_category = payload["divergence_category"]
        category = raw_category if isinstance(raw_category, str) else None
        mode = payload.get("mode")
        if isinstance(mode, str):
            modes[mode] += 1

        if legacy in LEGACY_DECISIONS and disposition in V21_DISPOSITIONS:
            matrix[legacy][disposition] += 1
        else:
            anomalies.append(
                {
                    "kind": "undefined_grid_input",
                    "legacy_decision": legacy,
                    "v21_fast_disposition": disposition,
                    **case,
                }
            )

        if category is None:
            categories["parity"] += 1
        else:
            categories[category] += 1
            if category not in DIVERGENCE_VOCABULARY:
                anomalies.append(
                    {"kind": "unknown_category", "category": category, **case}
                )
            if category in (DEGRADED_NO_SNAPSHOT, DEGRADED_COMPONENT_FAILURE):
                degraded[category] += 1
            elif (
                category in DIVERGENCE_VOCABULARY
                and (
                    legacy,
                    disposition,
                )
                in DIVERGENCE_GRID
            ):
                expected = DIVERGENCE_GRID[(legacy, disposition)]
                if expected != category:
                    anomalies.append(
                        {
                            "kind": "category_grid_mismatch",
                            "category": category,
                            "expected": expected,
                            "legacy_decision": legacy,
                            "v21_fast_disposition": disposition,
                            **case,
                        }
                    )
            if (
                category in section_14_cases
                and len(section_14_cases[category]) < case_limit
            ):
                section_14_cases[category].append(case)

    section_14 = {
        label: {
            "category": category,
            "count": categories.get(category, 0),
            "cases": section_14_cases[category],
            "cases_truncated": categories.get(category, 0)
            > len(section_14_cases[category]),
        }
        for label, category in SECTION_14_COMBINATIONS
    }
    return {
        "totals": {
            "records": total,
            "with_envelope": envelope_count,
            "parity": categories.get("parity", 0),
            "divergent": sum(
                count
                for name, count in categories.items()
                if name != "parity" and name in DIVERGENCE_VOCABULARY
            ),
        },
        "skipped": dict(sorted(skipped.items())),
        "matrix": matrix,
        "divergence_categories": dict(sorted(categories.items())),
        "degraded": dict(sorted(degraded.items())),
        "modes": dict(sorted(modes.items())),
        "section_14": section_14,
        "anomalies": anomalies,
    }


def build_report(
    records: Iterable[dict[str, Any]], *, source: str, case_limit: int
) -> dict[str, Any]:
    aggregation = aggregate_records(records, case_limit=case_limit)
    aggregation["ok"] = not aggregation["anomalies"]
    return {
        "schema_version": "1.0",
        "tool": "v21-shadow-divergence",
        "source": source,
        "vocabulary": {
            "grid_categories": sorted(DIVERGENCE_VOCABULARY),
            "degraded_categories": [
                DEGRADED_COMPONENT_FAILURE,
                DEGRADED_NO_SNAPSHOT,
            ],
        },
        **aggregation,
    }


def render_markdown(report: dict[str, Any]) -> str:
    matrix = report["matrix"]
    totals = report["totals"]
    lines = [
        "# V21-08 Shadow Divergence 离线分析报告",
        "",
        f"> 数据源：`{report['source']}`；聚合口径：`11_决策记录_V21-08前置.md` D2 受控词表。",
        "",
        "## 九宫格矩阵（legacy × v21）",
        "",
        "| legacy \\ v21 | " + " | ".join(V21_DISPOSITIONS) + " |",
        "|---" * (len(V21_DISPOSITIONS) + 1) + "|",
    ]
    for legacy in LEGACY_DECISIONS:
        cells = [str(matrix[legacy][disposition]) for disposition in V21_DISPOSITIONS]
        lines.append(f"| **{legacy}** | " + " | ".join(cells) + " |")
    lines.extend(
        [
            "",
            f"- 对角线（parity，`divergence_category=None`）：{totals['parity']} 条。",
            f"- 带信封记录合计：{totals['with_envelope']}；分叉（含降级类目）：{totals['divergent']}。",
            "",
            "## 降级类目分布",
            "",
            f"- `{DEGRADED_NO_SNAPSHOT}`：{report['degraded'].get(DEGRADED_NO_SNAPSHOT, 0)}",
            f"- `{DEGRADED_COMPONENT_FAILURE}`：{report['degraded'].get(DEGRADED_COMPONENT_FAILURE, 0)}",
            "",
            "## §14 三组合专项",
            "",
        ]
    )
    for label, entry in report["section_14"].items():
        lines.append(
            f"- {label} → `{entry['category']}`：{entry['count']} 条"
            + ("（case 列表已截断）" if entry["cases_truncated"] else "")
        )
        for case in entry["cases"]:
            lines.append(
                f"  - event_id=`{case['event_id']}` trace_id=`{case['trace_id']}`"
            )
    lines.extend(["", "## 跳过与异常", ""])
    skipped = report["skipped"] or {"无": 0}
    lines.extend(f"- 跳过 `{name}`：{count}" for name, count in skipped.items())
    if report["anomalies"]:
        lines.append("")
        for anomaly in report["anomalies"]:
            lines.append(
                f"- 异常：`{json.dumps(anomaly, ensure_ascii=False, sort_keys=True)}`"
            )
    else:
        lines.append("- 异常：无（词表封闭校验通过）")
    lines.extend(
        [
            "",
            "---",
            "",
            "- 本工具只读聚合审计旁路证据，不写库、不改契约、不接 Dashboard。",
            "- 聚合仅依赖 redaction/sanitize 后存活的浅层字段（divergence_category /",
            "  legacy_decision / v21_fast_disposition / mode / state_version / assessment_id）。",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        help="审计记录 JSONL 文件（每行一个 AuditEvent JSON dump）",
    )
    parser.add_argument(
        "--store",
        choices=("postgres",),
        help="从 guard-api 存储层只读拉取 policy_evaluation 审计记录",
    )
    parser.add_argument(
        "--database-url",
        help="postgres 连接串；缺省读 AGENTGUARD_TEST_DATABASE_URL 环境变量",
    )
    parser.add_argument("--limit", type=int, default=5000, help="store 读取上限")
    parser.add_argument(
        "--case-limit", type=int, default=50, help="单类目 case 列表上限"
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.input is not None and args.store is not None:
        raise ValueError("--input 与 --store 互斥，只能指定一种来源")
    if args.input is None and args.store is None:
        raise ValueError("必须指定 --input JSONL 文件或 --store 存储来源")
    if args.input is not None:
        records = load_jsonl_records(args.input)
        source = args.input.as_posix()
    else:
        database_url = args.database_url or os.getenv("AGENTGUARD_TEST_DATABASE_URL")
        if not database_url:
            raise ValueError(
                "--store postgres 需要 --database-url 或 AGENTGUARD_TEST_DATABASE_URL"
            )
        records = load_postgres_records(database_url, limit=args.limit)
        source = "postgres:policy_evaluation"
    report = build_report(records, source=source, case_limit=args.case_limit)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "divergence.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (args.output_dir / "divergence.md").write_text(
        render_markdown(report), encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {"ok": report["ok"], **report["totals"], "skipped": report["skipped"]},
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError) as exc:
        print(f"v21 shadow divergence error: {exc}", file=sys.stderr)
        raise SystemExit(2)
