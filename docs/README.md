# 文档地图

## 1. 文档目录

```text
docs/
├── README.md                  # 文档地图
├── repo_structure.md          # 仓库结构与职责
├── architecture.md            # 总体架构
├── interface_contract.md      # 事件模型与 API 契约
├── threat_model.md            # 威胁模型
├── core_design.md             # Agent Security Core
├── langgraph_adapter.md       # LangGraph 评测靶场
├── openclaw_plugin.md         # OpenClaw 插件接入
├── dashboard_design.md        # Dashboard 与审批
├── attackbench.md             # 攻击样本与评测指标
├── implementation_plan.md     # 阶段计划与验收
└── demo_script.md             # 演示脚本
```

## 2. 阅读顺序

### 快速了解

1. `README.md`
2. `repo_structure.md`
3. `architecture.md`

### 开发 Core

1. `interface_contract.md`
2. `core_design.md`
3. `implementation_plan.md`

### 开发 LangGraph

1. `langgraph_adapter.md`
2. `interface_contract.md`
3. `attackbench.md`

### 开发 OpenClaw

1. `openclaw_plugin.md`
2. `interface_contract.md`
3. `dashboard_design.md`

### 准备答辩

1. `architecture.md`
2. `threat_model.md`
3. `attackbench.md`
4. `demo_script.md`

## 3. 维护规则

- `interface_contract.md` 中字段变更必须同步 `schemas/`。
- Dashboard 只读取 Core API。
- Adapter 和 Plugin 不内置核心规则。
- 攻击样本真值由 `redteam/` 提供。
