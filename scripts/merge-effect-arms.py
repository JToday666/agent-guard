#!/usr/bin/env python3
"""Merge separate A0/A4 single-arm reports into a unified dual-arm effect report."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load_effect_module():
    import importlib.util as iu

    script = ROOT / "scripts" / "competition-v2-effect-run.py"
    spec = iu.spec_from_file_location("competition_v2_effect_run", str(script))
    assert spec is not None and spec.loader is not None
    mod = iu.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> None:
    mod = _load_effect_module()

    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a0-dir", type=Path, default=ROOT / "reports" / "v2-effect-a0-test")
    parser.add_argument("--a4-dir", type=Path, default=ROOT / "reports" / "v2-effect-a4-test")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "reports" / "v2-effect-merged")
    parser.add_argument("--llm-model", default="qwen3.7-plus")
    parser.add_argument("--llm-base-url", default="https://dashscope.aliyuncs.com/compatible-mode/v1")
    parser.add_argument("--semantic-model", default=None)
    parser.add_argument("--max-tool-rounds", type=int, default=None)
    args = parser.parse_args()

    a0_dir = args.a0_dir.resolve()
    a4_dir = args.a4_dir.resolve()
    out_dir = args.out_dir.resolve()

    # Load arm data
    a0_rows = json.loads((a0_dir / "arms" / "A0" / "run.json").read_text())
    a4_rows = json.loads((a4_dir / "arms" / "A4" / "run.json").read_text())
    a0_dur = json.loads((a0_dir / "arms" / "A0" / "durations.json").read_text())
    a4_dur = json.loads((a4_dir / "arms" / "A4" / "durations.json").read_text())
    a0_con = json.loads((a0_dir / "arms" / "A0" / "contracts.json").read_text())
    a4_con = json.loads((a4_dir / "arms" / "A4" / "contracts.json").read_text())

    from agentguard_langgraph_bench.bench.competition_models import load_competition_profile

    profile = load_competition_profile("competition-langgraph-v2")
    provider = mod.ProviderRuntimeConfig(
        provider_id="openai-compatible",
        model=args.llm_model,
        base_url=args.llm_base_url,
        api_key_env="COMPETITION_LLM_KEY",
        api_key="***",
    )

    arms_result = {
        "A0": {"rows": a0_rows, "case_durations_ms": a0_dur, "contracts": a0_con},
        "A4": {"rows": a4_rows, "case_durations_ms": a4_dur, "contracts": a4_con},
    }

    report = mod.build_effect_report(
        profile=profile,
        provider=provider,
        arms_result=arms_result,
        case_count=70,
        parallel=True,
    )
    report["arm_parallel"] = 10
    if args.max_tool_rounds:
        report["max_tool_rounds"] = args.max_tool_rounds
    if args.semantic_model:
        report["semantic_judgment"] = {
            "enabled": True,
            "arm_id": "A4",
            "model": args.semantic_model,
            "base_url": args.llm_base_url,
            "timeout_seconds": None,
        }
    else:
        report["semantic_judgment"] = {"enabled": False}
    report["merged_from"] = {
        "A0": str(a0_dir.relative_to(ROOT)),
        "A4": str(a4_dir.relative_to(ROOT)),
    }

    # Write output
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "effect-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2)
    )
    for arm_id in ("A0", "A4"):
        src = a0_dir if arm_id == "A0" else a4_dir
        dst = out_dir / "arms" / arm_id
        dst.mkdir(parents=True, exist_ok=True)
        shutil.copy(src / "arms" / arm_id / "run.json", dst / "run.json")
        shutil.copy(src / "arms" / arm_id / "durations.json", dst / "durations.json")

    mod._print_summary(report)
    print(f"\n合并报告: {out_dir / 'effect-report.json'}")


if __name__ == "__main__":
    main()
