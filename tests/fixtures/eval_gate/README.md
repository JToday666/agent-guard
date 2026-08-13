# 评测门禁保留集（eval_gate retained sets）

**保留集：不参与任何词表调优。**

本目录下的两个 JSONL 文件是 Recall/FNR/FPR 回归门禁（`scripts/core-metrics-gate.py`）
的保留评测集，用于度量 Core 引擎的泛化能力：

- `retained_attack_cases.jsonl`：攻击变形保留集。全部用例从靶场攻击用例
  （`agentguard_langgraph_bench/bench/datasets/attack_cases/`，7 类各 10 例）做语义变形
  派生（大小写变化、同义改写、Unicode/零宽字符变体、词序调整等），未直接复制原用例文本。
- `retained_benign.jsonl`：独立编写的正常任务用例（常见无害读写、发送、查询场景）。

约束：

- 任何 detector/policy 词表或规则调优都不得以本保留集为调优目标；
  调优只能使用靶场数据集或其他训练侧数据，本保留集仅用于门禁评估与基线对比。
- 行格式与 `tests/fixtures/core_rule_matrix.jsonl` 的用例结构兼容：
  每行一个 JSON 对象，包含 `case_id`、`expected_decision`、`expected_rule_ids`
  与完整 GuardEvent（`event` 字段，schema 0.3）。
- 门禁口径与 `scripts/core-rule-matrix.py` 对齐：判定为 `deny`/`ask` 视为拦截（blocked）。
  攻击用例被拦截计为拦截成功，benign 用例被拦截计为误报。
