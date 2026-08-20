"""Tests for scripts/effect-paired-significance.py (standard-library stats)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load_script() -> ModuleType:
    script = (
        Path(__file__).parents[1] / "scripts" / "effect-paired-significance.py"
    )
    spec = importlib.util.spec_from_file_location(
        "effect_paired_significance", script
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = _load_script()


def _row(
    case_id: str,
    *,
    malicious: bool = True,
    valid: bool = True,
    attack_success: bool | None = False,
    overblocked: bool | None = False,
    attack_type: str = "jailbreak",
) -> dict:
    return {
        "case_id": case_id,
        "attack_type": attack_type,
        "is_malicious": malicious,
        "run_valid": valid,
        "attack_success": attack_success if (valid and malicious) else None,
        "overblocked": overblocked if (valid and not malicious) else None,
        "task_success": True,
    }


# ---------------------------------------------------------------------------
# McNemar exact test
# ---------------------------------------------------------------------------


def test_mcnemar_all_concordant_p_is_one():
    result = mod.mcnemar_exact(0, 0, alpha=0.05)
    assert result["p_value"] == pytest.approx(1.0)
    assert result["discordant_pairs"] == 0
    assert result["significant"] is False
    assert result["mcnemar_chi2_corrected"] is None


def test_mcnemar_all_discordant_matches_binomial():
    # b=0, c=5 -> p = min(1, 2 * 0.5**5) = 0.0625
    result = mod.mcnemar_exact(0, 5, alpha=0.05)
    assert result["p_value"] == pytest.approx(0.0625)
    assert result["significant"] is False  # not significant at 0.05


def test_mcnemar_hand_computed_two_sided_p():
    # b=1, c=9, n=10 -> p = 2 * (C(10,0) + C(10,1)) / 2**10 = 22/1024
    result = mod.mcnemar_exact(1, 9, alpha=0.05)
    assert result["p_value"] == pytest.approx(22 / 1024)
    assert result["significant"] is True
    assert result["mcnemar_chi2_corrected"] == pytest.approx((8 - 1) ** 2 / 10)


def test_mcnemar_symmetric_in_arms():
    forward = mod.mcnemar_exact(2, 7, alpha=0.05)
    backward = mod.mcnemar_exact(7, 2, alpha=0.05)
    assert forward["p_value"] == pytest.approx(backward["p_value"])


def test_binom_cdf_boundaries():
    assert mod.binom_cdf(-1, 4) == 0.0
    assert mod.binom_cdf(4, 4) == 1.0
    assert mod.binom_cdf(0, 3) == pytest.approx(0.125)


# ---------------------------------------------------------------------------
# Wilson score interval
# ---------------------------------------------------------------------------


def test_wilson_matches_hand_computation():
    # k=5, n=20, alpha=0.05, z=1.959964 (standard normal quantile):
    # center = (p + z^2/2n) / (1 + z^2/n), half = z/(1+z^2/n) *
    # sqrt(p(1-p)/n + z^2/4n^2) -> [0.11186, 0.46870]
    result = mod.wilson_interval(5, 20, alpha=0.05)
    assert result["point_estimate"] == pytest.approx(0.25)
    assert result["ci_lower"] == pytest.approx(0.11186, abs=1e-4)
    assert result["ci_upper"] == pytest.approx(0.46870, abs=1e-4)


def test_wilson_zero_successes_lower_bound_is_zero():
    result = mod.wilson_interval(0, 10, alpha=0.05)
    assert result["point_estimate"] == 0.0
    assert result["ci_lower"] == pytest.approx(0.0, abs=1e-12)
    assert result["ci_upper"] > 0.0


def test_wilson_all_successes_upper_bound_is_one():
    result = mod.wilson_interval(10, 10, alpha=0.05)
    assert result["ci_upper"] == pytest.approx(1.0, abs=1e-12)
    assert result["ci_lower"] < 1.0


def test_wilson_no_trials_returns_nones():
    result = mod.wilson_interval(0, 0, alpha=0.05)
    assert result["point_estimate"] is None
    assert result["ci_lower"] is None
    assert result["ci_upper"] is None


# ---------------------------------------------------------------------------
# end-to-end report structure from inline rows
# ---------------------------------------------------------------------------


def _sample_rows():
    baseline = [
        _row("M1", attack_success=True),
        _row("M2", attack_success=True),
        _row("M3"),
        _row("M4", attack_type="prompt_injection"),
        _row("M5", attack_type="prompt_injection"),
        _row("M6", valid=False),
        _row("B1", malicious=False),
    ]
    product = [
        _row("M1"),
        _row("M2"),
        _row("M3"),
        _row("M4", attack_type="prompt_injection", attack_success=True),
        _row("M5", attack_type="prompt_injection"),
        _row("M6", valid=False),
        _row("B1", malicious=False, overblocked=True),
    ]
    return baseline, product


@pytest.fixture(scope="module")
def sample_report():
    baseline, product = _sample_rows()
    return mod.build_report(
        Path("/nonexistent/artifacts"),
        alpha=0.05,
        report_path=Path("/nonexistent/artifacts/effect-report.json"),
        baseline_rows=baseline,
        product_rows=product,
    )


def test_report_top_level_structure(sample_report):
    for key in (
        "schema_version",
        "generated_at",
        "alpha",
        "inputs",
        "sample_sizes",
        "mcnemar",
        "wilson_confidence_intervals",
        "per_attack_type_paired_asr",
        "sensitivity",
        "notes",
    ):
        assert key in sample_report
    assert sample_report["alpha"] == 0.05
    assert sample_report["inputs"]["artifacts_dir"] == "/nonexistent/artifacts"


def test_report_sample_sizes(sample_report):
    sizes = sample_report["sample_sizes"]
    assert sizes["baseline_rows"] == 7
    assert sizes["product_rows"] == 7
    # M6 invalid in both arms -> excluded from paired-valid, kept malicious.
    assert sizes["paired_valid_malicious_count"] == 5
    assert sizes["shared_malicious_count"] == 6


def test_report_mcnemar_contingency(sample_report):
    mcnemar = sample_report["mcnemar"]
    contingency = mcnemar["contingency"]
    assert contingency["baseline_only_success"] == 2  # M1, M2 blocked by product
    assert contingency["product_only_success"] == 1  # M4 succeeded only on product
    assert contingency["both_success"] == 0
    assert contingency["both_fail"] == 2
    # p = min(1, 2 * (C(3,0)+C(3,1)) / 8) = 1.0
    assert mcnemar["p_value"] == pytest.approx(1.0)


def test_report_wilson_sections(sample_report):
    wilson = sample_report["wilson_confidence_intervals"]
    # Per-arm ASR over valid malicious rows (5 per arm, 2 / 1 successes).
    baseline_asr = wilson["baseline"]["asr_valid_malicious"]
    assert baseline_asr["point_estimate"] == pytest.approx(2 / 5)
    assert 0.0 < baseline_asr["ci_lower"] < 2 / 5 < baseline_asr["ci_upper"] < 1.0
    # FPR: product overblocked the single benign valid case.
    product_fpr = wilson["product"]["fpr_benign_overblock"]
    assert product_fpr["point_estimate"] == pytest.approx(1.0)
    baseline_fpr = wilson["baseline"]["fpr_benign_overblock"]
    assert baseline_fpr["point_estimate"] == pytest.approx(0.0)
    # Blocked-successful-attack rate: both baseline paired successes blocked.
    blocked = wilson["blocked_successful_attack_rate"]
    assert blocked["point_estimate"] == pytest.approx(1.0)
    assert blocked["trials"] == 2


def test_report_per_attack_type(sample_report):
    per_type = sample_report["per_attack_type_paired_asr"]
    assert set(per_type) == {"jailbreak", "prompt_injection"}
    jailbreak = per_type["jailbreak"]
    assert jailbreak["paired_valid_count"] == 3
    assert jailbreak["baseline_asr"] == pytest.approx(2 / 3)
    assert jailbreak["product_asr"] == pytest.approx(0.0)
    injection = per_type["prompt_injection"]
    assert injection["paired_valid_count"] == 2
    assert injection["baseline_asr"] == pytest.approx(0.0)
    assert injection["product_asr"] == pytest.approx(1 / 2)


def test_report_sensitivity(sample_report):
    sensitivity = sample_report["sensitivity"]
    paired_only = sensitivity["paired_valid_only"]
    assert paired_only["case_count"] == 5
    assert paired_only["baseline_asr"] == pytest.approx(2 / 5)
    assert paired_only["product_asr"] == pytest.approx(1 / 5)
    pessimistic = sensitivity["invalid_as_attack_success"]
    # M6 invalid in both arms counts as success for both arms.
    assert pessimistic["case_count"] == 6
    assert pessimistic["baseline_asr"] == pytest.approx(3 / 6)
    assert pessimistic["product_asr"] == pytest.approx(2 / 6)


def test_small_sample_note_present(sample_report):
    assert any("small" in note for note in sample_report["notes"])


# ---------------------------------------------------------------------------
# arm 解析：effect-run 平铺布局 / 消融 repeat 布局（泛化任意两臂）
# ---------------------------------------------------------------------------


def _write_run_json(base: Path, rows: list[dict]) -> None:
    base.mkdir(parents=True, exist_ok=True)
    (base / "run.json").write_text(json.dumps(rows), encoding="utf-8")


def test_default_flat_layout_keeps_a0_a4_behavior(tmp_path: Path):
    """默认 A0/A4 + effect-run 平铺布局：行为与原版完全一致。"""

    _write_run_json(tmp_path / "arms" / "A0", [_row("M1", attack_success=True)])
    _write_run_json(tmp_path / "arms" / "A4", [_row("M1")])

    rows, arm_dir, repeat = mod.load_arm_rows(tmp_path, "A0")
    assert len(rows) == 1
    assert arm_dir == tmp_path / "arms" / "A0"
    assert repeat is None

    report = mod.build_report(tmp_path, alpha=0.05)
    inputs = report["inputs"]
    assert inputs["baseline_arm_id"] == "A0"
    assert inputs["product_arm_id"] == "A4"
    assert inputs["baseline_arm_dir"] == str(tmp_path / "arms" / "A0")
    assert inputs["baseline_repeat_index"] is None
    assert inputs["product_repeat_index"] is None
    # 平铺路径仍是 inputs 里记录的实际行集路径。
    assert inputs["baseline_rows_path"].endswith("arms/A0/run.json")


def test_custom_labels_resolve_ablation_repeat_layout(tmp_path: Path):
    """自定义 label（消融臂）解析 repeat 布局并记录溯源路径/索引。"""

    _write_run_json(
        tmp_path / "repeat-0" / "arms" / "core-off",
        [_row("M1", attack_success=True)],
    )
    _write_run_json(
        tmp_path / "repeat-0" / "arms" / "no-memory-guard", [_row("M1")]
    )

    report = mod.build_report(
        tmp_path,
        alpha=0.05,
        baseline_arm="core-off",
        product_arm="no-memory-guard",
    )
    inputs = report["inputs"]
    assert inputs["baseline_arm_id"] == "core-off"
    assert inputs["product_arm_id"] == "no-memory-guard"
    assert inputs["baseline_arm_dir"] == str(
        tmp_path / "repeat-0" / "arms" / "core-off"
    )
    assert inputs["baseline_repeat_index"] == 0
    assert inputs["product_repeat_index"] == 0
    # 配对统计来自 repeat 布局行集：baseline 攻击得手、product 阻止。
    contingency = report["mcnemar"]["contingency"]
    assert contingency["baseline_only_success"] == 1
    assert contingency["product_only_success"] == 0


def test_multiple_repeats_pick_largest_index(tmp_path: Path):
    """多个 repeat 目录默认取索引最大的一轮。"""

    _write_run_json(
        tmp_path / "repeat-0" / "arms" / "full", [_row("M1", attack_success=True)]
    )
    _write_run_json(
        tmp_path / "repeat-1" / "arms" / "full", [_row("M1", attack_success=True)]
    )
    _write_run_json(tmp_path / "repeat-2" / "arms" / "full", [_row("M1")])
    _write_run_json(
        tmp_path / "repeat-2" / "arms" / "core-off",
        [_row("M1", attack_success=True)],
    )

    rows, arm_dir, repeat = mod.load_arm_rows(tmp_path, "full")
    assert repeat == 2
    assert arm_dir == tmp_path / "repeat-2" / "arms" / "full"
    # 取到的是 repeat-2 的行（attack_success=False，而非旧轮的 True）。
    assert rows[0]["attack_success"] is False

    report = mod.build_report(
        tmp_path, alpha=0.05, baseline_arm="core-off", product_arm="full"
    )
    assert report["inputs"]["baseline_repeat_index"] == 2
    assert report["inputs"]["product_repeat_index"] == 2


def test_explicit_repeat_index_pins_one_round(tmp_path: Path):
    """--repeat 显式指定：只认该轮，覆盖默认最大索引规则。"""

    _write_run_json(tmp_path / "repeat-0" / "arms" / "full", [_row("M1")])
    _write_run_json(
        tmp_path / "repeat-1" / "arms" / "full", [_row("M1", attack_success=True)]
    )

    rows, _, repeat = mod.load_arm_rows(tmp_path, "full", repeat_index=0)
    assert repeat == 0
    assert rows[0]["attack_success"] is False

    # 显式索引不存在时报错（扫描列表里含已存在的其它轮路径）。
    with pytest.raises(FileNotFoundError, match="repeat-3"):
        mod.load_arm_rows(tmp_path, "full", repeat_index=3)


def test_missing_arm_lists_scanned_paths(tmp_path: Path):
    """找不到时报错信息列出实际扫描过的路径（平铺 + repeat 布局）。"""

    _write_run_json(tmp_path / "repeat-0" / "arms" / "full", [_row("M1")])

    with pytest.raises(FileNotFoundError) as excinfo:
        mod.load_arm_rows(tmp_path, "no-such-arm")
    message = str(excinfo.value)
    assert "no-such-arm" in message
    assert str(tmp_path / "arms" / "no-such-arm" / "run.json") in message
    assert (
        str(tmp_path / "repeat-0" / "arms" / "no-such-arm" / "run.json") in message
    )


def test_explicit_arm_overrides_effect_report_ids(tmp_path: Path):
    """显式 --baseline-arm/--product-arm 优先于 effect-report.json 记录；
    未显式传值时沿用 report 里的 id（effect-run 兼容不变）。"""

    (tmp_path / "effect-report.json").write_text(
        json.dumps({"paired": {"baseline_arm_id": "A0", "product_arm_id": "A4"}}),
        encoding="utf-8",
    )
    _write_run_json(tmp_path / "repeat-0" / "arms" / "full", [_row("M1")])
    _write_run_json(tmp_path / "repeat-0" / "arms" / "core-off", [_row("M1")])

    report = mod.build_report(
        tmp_path, alpha=0.05, baseline_arm="core-off", product_arm="full"
    )
    assert report["inputs"]["baseline_arm_id"] == "core-off"
    assert report["inputs"]["product_arm_id"] == "full"

    # 未显式传值时沿用 effect-report.json 的 A0/A4（补齐平铺布局产物）。
    _write_run_json(tmp_path / "arms" / "A0", [_row("M1", attack_success=True)])
    _write_run_json(tmp_path / "arms" / "A4", [_row("M1")])
    legacy = mod.build_report(tmp_path, alpha=0.05)
    assert legacy["inputs"]["baseline_arm_id"] == "A0"
    assert legacy["inputs"]["product_arm_id"] == "A4"
    assert legacy["inputs"]["baseline_repeat_index"] is None
