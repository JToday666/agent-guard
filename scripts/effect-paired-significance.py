#!/usr/bin/env python3
"""Paired significance aggregation for dual-arm (A0 vs A4) effect artifacts.

Reads a dual-arm effect artifact directory (``effect-report.json`` plus
``arms/{arm}/run.json`` row-level data) and emits a single self-describing
JSON report containing:

* McNemar exact (binomial) test on paired-valid malicious cases -- do the
  two arms differ in attack-success outcomes?
* Wilson score confidence intervals for ASR, benign overblock FPR and the
  blocked-successful-attack rate of each arm;
* descriptive paired ASR broken down by attack type;
* a sensitivity analysis contrasting "paired-valid only" ASR with a
  pessimistic variant that counts invalid runs as attack successes.

Arm selection defaults to A0/A4 (effect-run flat layout ``arms/{arm}``).
``--baseline-arm`` / ``--product-arm`` generalize the script to any two
arms, including the ablation matrix layout ``repeat-*/arms/<label>/run.json``
(labels like ``full`` / ``no-memory-guard``); when several repeat
directories exist the largest index wins unless ``--repeat`` pins one.

Standard library only (no scipy/statsmodels).  The pairing rule mirrors
``agentguard_langgraph_bench.bench.v2_effect_metrics.compute_paired_metrics``:
a case is paired-valid when it is present in both arms, ``run_valid`` is
true in both, and the case is malicious.

Usage:
    uv run python scripts/effect-paired-significance.py \
        --artifacts-dir reports/v2-effect-qwen37-merged-r30-p5 \
        --out /tmp/significance-demo.json [--alpha 0.05]

    # 消融产物任意两臂对比（repeat 布局；多轮默认取索引最大）
    uv run python scripts/effect-paired-significance.py \
        --artifacts-dir reports/ablation-replay-full \
        --baseline-arm core-off --product-arm no-memory-guard \
        --out /tmp/ablation-significance.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import NormalDist
from typing import Any

SIGNIFICANCE_SCHEMA_VERSION = "dual-arm-paired-significance/1.0"
DEFAULT_BASELINE_ARM_ID = "A0"
DEFAULT_PRODUCT_ARM_ID = "A4"


# ---------------------------------------------------------------------------
# statistics primitives
# ---------------------------------------------------------------------------


def binom_cdf(k: int, n: int, p: float = 0.5) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    total = 0.0
    for i in range(k + 1):
        total += math.comb(n, i) * (p**i) * ((1.0 - p) ** (n - i))
    return min(1.0, total)


def mcnemar_exact(
    baseline_only: int,
    product_only: int,
    *,
    alpha: float,
) -> dict[str, Any]:
    """Exact McNemar test (two-sided binomial on discordant pairs).

    ``baseline_only`` = attacks succeeding on baseline but blocked on the
    product arm; ``product_only`` = the reverse.  Under H0 each discordant
    pair is a fair coin flip, so the two-sided p value is
    ``min(1, 2 * P(X <= min(b, c)))`` with ``X ~ Binomial(b + c, 0.5)``
    (the same convention as statsmodels' exact McNemar).
    """
    b, c = int(baseline_only), int(product_only)
    n = b + c
    if n == 0:
        p_value = 1.0
    else:
        p_value = min(1.0, 2.0 * binom_cdf(min(b, c), n, 0.5))
    chi2_statistic = None
    if n > 0:
        # Continuity-corrected McNemar chi-square, reported for reference.
        chi2_statistic = ((abs(b - c) - 1.0) ** 2) / n
    return {
        "method": "exact_binomial_two_sided",
        "alpha": alpha,
        "contingency": {
            "both_success": None,  # filled in by the caller
            "baseline_only_success": b,
            "product_only_success": c,
            "both_fail": None,  # filled in by the caller
        },
        "discordant_pairs": n,
        "test_statistic": 0.5 * n if n else 0.0,  # expected under H0
        "mcnemar_chi2_corrected": chi2_statistic,
        "p_value": p_value,
        "significant": bool(p_value < alpha),
    }


def wilson_interval(
    successes: int, trials: int, *, alpha: float
) -> dict[str, Any]:
    """Wilson score interval for a binomial proportion."""
    result: dict[str, Any] = {
        "successes": int(successes),
        "trials": int(trials),
        "alpha": alpha,
        "point_estimate": None,
        "ci_lower": None,
        "ci_upper": None,
    }
    if trials <= 0:
        return result
    p_hat = successes / trials
    z = NormalDist().inv_cdf(1.0 - alpha / 2.0)
    z2 = z * z
    denominator = 1.0 + z2 / trials
    center = (p_hat + z2 / (2.0 * trials)) / denominator
    half = (
        z
        / denominator
        * math.sqrt(p_hat * (1.0 - p_hat) / trials + z2 / (4.0 * trials * trials))
    )
    result["point_estimate"] = p_hat
    result["ci_lower"] = max(0.0, center - half)
    result["ci_upper"] = min(1.0, center + half)
    return result


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator > 0 else None


# ---------------------------------------------------------------------------
# artifact loading & pairing
# ---------------------------------------------------------------------------


def _resolve_arm_dir(
    artifacts_dir: Path,
    arm: str,
    *,
    repeat_index: int | None = None,
) -> tuple[Path, int | None, list[str]]:
    """解析一个臂的行集目录，兼容两种产物布局。

    优先 effect-run 平铺布局 ``<artifacts>/arms/<arm>/run.json``；不存在
    则扫描消融布局 ``<artifacts>/repeat-*/arms/<arm>/run.json``（多个
    repeat 目录时默认取索引最大的一轮；``repeat_index`` 非 None 时只认
    该轮，找不到即报错——平铺布局无 repeat 概念）。返回 ``(arm 目录,
    repeat 索引或 None, 实际扫描过的 run.json 路径列表)``；均未命中时
    报错并列出扫描过的路径。
    """

    # 先扫全部 repeat-N 目录（与该臂是否命中解耦），scanned 才能如实
    # 列出候选路径；重复目录名后缀须为纯数字，其余（如 repeat-abc）忽略。
    repeat_dirs = sorted(
        (
            (int(entry.name[len("repeat-") :]), entry)
            for entry in artifacts_dir.glob("repeat-*")
            if entry.is_dir() and entry.name[len("repeat-") :].isdigit()
        ),
    )
    repeat_entries = [
        (index, repeat_dir / "arms" / arm)
        for index, repeat_dir in repeat_dirs
        if (repeat_dir / "arms" / arm / "run.json").is_file()
    ]
    scanned = [
        str(artifacts_dir / "arms" / arm / "run.json"),
        *(
            str(repeat_dir / "arms" / arm / "run.json")
            for _, repeat_dir in repeat_dirs
        ),
    ]
    if repeat_index is not None:
        for index, arm_dir in repeat_entries:
            if index == repeat_index:
                return arm_dir, repeat_index, scanned
        raise FileNotFoundError(
            f"arm row data not found for {arm} at repeat-{repeat_index}; "
            f"scanned: {scanned}"
        )
    flat_run = artifacts_dir / "arms" / arm / "run.json"
    if flat_run.is_file():
        return flat_run.parent, None, scanned
    if repeat_entries:
        index, arm_dir = max(repeat_entries)
        return arm_dir, index, scanned
    raise FileNotFoundError(f"arm row data not found: {arm}; scanned: {scanned}")


def load_arm_rows(
    artifacts_dir: Path,
    arm: str,
    *,
    repeat_index: int | None = None,
) -> tuple[list[dict[str, Any]], Path, int | None]:
    """加载一个臂的 run.json 行集（布局解析见 ``_resolve_arm_dir``）。

    返回 ``(rows, arm 目录, repeat 索引或 None)``。
    """

    arm_dir, resolved_repeat, _scanned = _resolve_arm_dir(
        artifacts_dir, arm, repeat_index=repeat_index
    )
    path = arm_dir / "run.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"expected a JSON list of case rows in {path}")
    return payload, arm_dir, resolved_repeat


def index_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(row["case_id"]): row
        for row in rows
        if row.get("case_id") is not None
    }


def build_pairs(
    baseline_rows: list[dict[str, Any]],
    product_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Pair rows by case_id following the compute_paired_metrics rule."""
    baseline_by_id = index_rows(baseline_rows)
    product_by_id = index_rows(product_rows)
    shared_ids = sorted(set(baseline_by_id) & set(product_by_id))

    paired_valid: list[dict[str, Any]] = []
    for case_id in shared_ids:
        baseline = baseline_by_id[case_id]
        product = product_by_id[case_id]
        if (
            baseline.get("run_valid") is True
            and product.get("run_valid") is True
            and baseline.get("is_malicious") is True
        ):
            paired_valid.append(
                {
                    "case_id": case_id,
                    "attack_type": baseline.get("attack_type"),
                    "baseline_success": baseline.get("attack_success") is True,
                    "product_success": product.get("attack_success") is True,
                }
            )

    # Shared malicious cases regardless of validity (sensitivity analysis).
    shared_malicious: list[dict[str, Any]] = []
    for case_id in shared_ids:
        baseline = baseline_by_id[case_id]
        product = product_by_id[case_id]
        if baseline.get("is_malicious") is True:
            shared_malicious.append(
                {
                    "case_id": case_id,
                    "baseline_success_pessimistic": _pessimistic_success(baseline),
                    "product_success_pessimistic": _pessimistic_success(product),
                }
            )

    return {
        "shared_case_count": len(shared_ids),
        "paired_valid": paired_valid,
        "shared_malicious": shared_malicious,
    }


def _pessimistic_success(row: dict[str, Any]) -> bool:
    """Invalid run counts as attack success; valid rows use attack_success."""
    if row.get("run_valid") is not True:
        return True
    return row.get("attack_success") is True


# ---------------------------------------------------------------------------
# report sections
# ---------------------------------------------------------------------------


def paired_mcnemar(paired_valid: list[dict[str, Any]], *, alpha: float) -> dict[str, Any]:
    both_success = sum(
        1 for p in paired_valid if p["baseline_success"] and p["product_success"]
    )
    baseline_only = sum(
        1 for p in paired_valid if p["baseline_success"] and not p["product_success"]
    )
    product_only = sum(
        1 for p in paired_valid if not p["baseline_success"] and p["product_success"]
    )
    both_fail = sum(
        1 for p in paired_valid if not p["baseline_success"] and not p["product_success"]
    )
    result = mcnemar_exact(baseline_only, product_only, alpha=alpha)
    result["contingency"]["both_success"] = both_success
    result["contingency"]["both_fail"] = both_fail
    result["paired_valid_count"] = len(paired_valid)
    return result


def per_attack_type_asr(paired_valid: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for pair in paired_valid:
        grouped.setdefault(str(pair["attack_type"]), []).append(pair)
    section: dict[str, Any] = {}
    for attack_type in sorted(grouped):
        pairs = grouped[attack_type]
        count = len(pairs)
        baseline_success = sum(1 for p in pairs if p["baseline_success"])
        product_success = sum(1 for p in pairs if p["product_success"])
        section[attack_type] = {
            "paired_valid_count": count,
            "baseline_attack_success": baseline_success,
            "product_attack_success": product_success,
            "baseline_asr": _ratio(baseline_success, count),
            "product_asr": _ratio(product_success, count),
            "note": "descriptive only; sample size may be too small for inference",
        }
    return section


def sensitivity_section(
    paired_valid: list[dict[str, Any]],
    shared_malicious: list[dict[str, Any]],
) -> dict[str, Any]:
    count = len(paired_valid)
    paired_only = {
        "definition": "both arms run_valid and case is malicious",
        "case_count": count,
        "baseline_asr": _ratio(
            sum(1 for p in paired_valid if p["baseline_success"]), count
        ),
        "product_asr": _ratio(
            sum(1 for p in paired_valid if p["product_success"]), count
        ),
    }
    pessimistic_count = len(shared_malicious)
    pessimistic = {
        "definition": (
            "all malicious cases present in both arms; invalid runs "
            "(run_valid != true) are counted as attack successes"
        ),
        "case_count": pessimistic_count,
        "baseline_asr": _ratio(
            sum(1 for p in shared_malicious if p["baseline_success_pessimistic"]),
            pessimistic_count,
        ),
        "product_asr": _ratio(
            sum(1 for p in shared_malicious if p["product_success_pessimistic"]),
            pessimistic_count,
        ),
    }
    return {
        "paired_valid_only": paired_only,
        "invalid_as_attack_success": pessimistic,
    }


def wilson_section(
    baseline_rows: list[dict[str, Any]],
    product_rows: list[dict[str, Any]],
    paired_valid: list[dict[str, Any]],
    *,
    alpha: float,
) -> dict[str, Any]:
    """Wilson CIs for ASR / FPR / blocked-successful-attack rate."""

    def _arm_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
        valid = [row for row in rows if row.get("run_valid") is True]
        malicious = [row for row in valid if row.get("is_malicious") is True]
        benign = [row for row in valid if row.get("is_malicious") is False]
        attack_success = sum(
            1 for row in malicious if row.get("attack_success") is True
        )
        overblocked = sum(1 for row in benign if row.get("overblocked") is True)
        return {
            "asr_valid_malicious": wilson_interval(
                attack_success, len(malicious), alpha=alpha
            ),
            "fpr_benign_overblock": wilson_interval(
                overblocked, len(benign), alpha=alpha
            ),
        }

    baseline_valid_asr = sum(1 for p in paired_valid if p["baseline_success"])
    product_valid_asr = sum(1 for p in paired_valid if p["product_success"])
    blocked_successful = sum(
        1
        for p in paired_valid
        if p["baseline_success"] and not p["product_success"]
    )
    return {
        "baseline": _arm_rows(baseline_rows),
        "product": _arm_rows(product_rows),
        "paired_valid_asr_baseline": wilson_interval(
            baseline_valid_asr, len(paired_valid), alpha=alpha
        ),
        "paired_valid_asr_product": wilson_interval(
            product_valid_asr, len(paired_valid), alpha=alpha
        ),
        "blocked_successful_attack_rate": {
            "definition": (
                "fraction of paired cases where the baseline attack succeeded "
                "but the product arm blocked it; denominator is baseline "
                "attack successes in the paired-valid set"
            ),
            **wilson_interval(blocked_successful, baseline_valid_asr, alpha=alpha),
        },
    }


def build_report(
    artifacts_dir: Path,
    *,
    alpha: float,
    report_path: Path | None = None,
    baseline_rows: list[dict[str, Any]] | None = None,
    product_rows: list[dict[str, Any]] | None = None,
    baseline_arm: str | None = None,
    product_arm: str | None = None,
    repeat_index: int | None = None,
) -> dict[str, Any]:
    """Assemble the full significance report.

    Rows may be passed directly (unit tests); otherwise they are loaded from
    ``artifacts_dir/arms/{arm}/run.json`` (effect-run flat layout) or
    ``artifacts_dir/repeat-*/arms/{arm}/run.json`` (ablation layout, largest
    repeat index by default).  Explicit ``baseline_arm``/``product_arm``
    take precedence over ids recorded in ``effect-report.json``.
    """
    baseline_arm_id = (
        baseline_arm if baseline_arm is not None else DEFAULT_BASELINE_ARM_ID
    )
    product_arm_id = (
        product_arm if product_arm is not None else DEFAULT_PRODUCT_ARM_ID
    )
    effect_report: dict[str, Any] | None = None
    if report_path is None:
        report_path = artifacts_dir / "effect-report.json"
    if report_path.is_file():
        effect_report = json.loads(report_path.read_text(encoding="utf-8"))
        paired_meta = effect_report.get("paired") or {}
        # 显式 CLI 传值优先；未传时沿用 effect-report.json 的记录
        # （effect-run 兼容：默认路径行为不变）。
        if baseline_arm is None and paired_meta.get("baseline_arm_id"):
            baseline_arm_id = str(paired_meta["baseline_arm_id"])
        if product_arm is None and paired_meta.get("product_arm_id"):
            product_arm_id = str(paired_meta["product_arm_id"])
    baseline_dir = artifacts_dir / "arms" / baseline_arm_id
    baseline_repeat: int | None = None
    product_dir = artifacts_dir / "arms" / product_arm_id
    product_repeat: int | None = None
    if baseline_rows is None:
        baseline_rows, baseline_dir, baseline_repeat = load_arm_rows(
            artifacts_dir, baseline_arm_id, repeat_index=repeat_index
        )
    if product_rows is None:
        product_rows, product_dir, product_repeat = load_arm_rows(
            artifacts_dir, product_arm_id, repeat_index=repeat_index
        )

    pairs = build_pairs(baseline_rows, product_rows)
    paired_valid = pairs["paired_valid"]
    shared_malicious = pairs["shared_malicious"]

    notes: list[str] = []
    if effect_report is not None:
        recorded_ids = (effect_report.get("paired") or {}).get("paired_case_ids")
        if isinstance(recorded_ids, list):
            recomputed = {p["case_id"] for p in paired_valid}
            if recomputed != set(recorded_ids):
                notes.append(
                    "paired case ids recomputed from rows differ from "
                    "effect-report.json paired_case_ids"
                )
    if len(paired_valid) < 10:
        notes.append(
            "paired-valid sample is small; interpret p values and CIs cautiously"
        )

    return {
        "schema_version": SIGNIFICANCE_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alpha": alpha,
        "inputs": {
            "artifacts_dir": str(artifacts_dir),
            "effect_report": str(report_path) if report_path.is_file() else None,
            "baseline_arm_id": baseline_arm_id,
            "product_arm_id": product_arm_id,
            # 实际解析到的行集路径/目录与 repeat 索引（平铺布局为 None），
            # 便于消融产物溯源。
            "baseline_rows_path": str(baseline_dir / "run.json"),
            "product_rows_path": str(product_dir / "run.json"),
            "baseline_arm_dir": str(baseline_dir),
            "product_arm_dir": str(product_dir),
            "baseline_repeat_index": baseline_repeat,
            "product_repeat_index": product_repeat,
        },
        "sample_sizes": {
            "baseline_rows": len(baseline_rows),
            "product_rows": len(product_rows),
            "shared_case_count": pairs["shared_case_count"],
            "paired_valid_malicious_count": len(paired_valid),
            "shared_malicious_count": len(shared_malicious),
        },
        "mcnemar": paired_mcnemar(paired_valid, alpha=alpha),
        "wilson_confidence_intervals": wilson_section(
            baseline_rows, product_rows, paired_valid, alpha=alpha
        ),
        "per_attack_type_paired_asr": per_attack_type_asr(paired_valid),
        "sensitivity": sensitivity_section(paired_valid, shared_malicious),
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate paired significance statistics (McNemar exact test, "
            "Wilson CIs, per-attack-type paired ASR, sensitivity) from a "
            "dual-arm effect artifact directory."
        )
    )
    parser.add_argument(
        "--artifacts-dir",
        required=True,
        type=Path,
        help=(
            "dual-arm artifact directory containing effect-report.json and "
            "arms/{A0,A4}/run.json"
        ),
    )
    parser.add_argument(
        "--out", required=True, type=Path, help="output JSON report path"
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=0.05,
        help="significance level / CI complement (default 0.05)",
    )
    parser.add_argument(
        "--baseline-arm",
        default=None,
        help=(
            "baseline arm id/label (default A0; falls back to "
            "effect-report.json paired.baseline_arm_id when omitted; accepts "
            "ablation labels like core-off/full)"
        ),
    )
    parser.add_argument(
        "--product-arm",
        default=None,
        help=(
            "product arm id/label (default A4; falls back to "
            "effect-report.json paired.product_arm_id when omitted; accepts "
            "ablation labels like no-memory-guard)"
        ),
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=None,
        help=(
            "ablation 布局显式 repeat 索引（不给时：多个 repeat 目录取索引"
            "最大的一轮）"
        ),
    )
    args = parser.parse_args(argv)

    artifacts_dir: Path = args.artifacts_dir
    if not artifacts_dir.is_dir():
        print(f"error: artifacts dir not found: {artifacts_dir}", file=sys.stderr)
        return 2
    if not (0.0 < args.alpha < 1.0):
        print("error: --alpha must be in (0, 1)", file=sys.stderr)
        return 2

    try:
        report = build_report(
            artifacts_dir,
            alpha=args.alpha,
            baseline_arm=args.baseline_arm,
            product_arm=args.product_arm,
            repeat_index=args.repeat,
        )
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    mcnemar = report["mcnemar"]
    print(f"wrote {args.out}")
    print(
        "paired-valid malicious cases: "
        f"{report['sample_sizes']['paired_valid_malicious_count']}"
    )
    print(
        f"mcnemar exact p = {mcnemar['p_value']:.6g} "
        f"(significant at alpha={args.alpha}: {mcnemar['significant']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
