# Dashboard 前端文档

本目录维护 Dashboard 前端内部文档。跨端接口、事件模型和系统架构以仓库根目录文档为准，前端文档只记录前端如何消费这些事实。

## 文档结构

```text
apps/dashboard/docs/
├── 02-architecture/
│   └── data-flow.md
├── 03-delivery/
│   ├── dashboard-change-summary.md
│   └── dashboard-validation-report.md
└── 04-规范/
    ├── 前端UI设计规范.md
    └── 文档维护约定.md
```

## 阅读入口

- [前端 UI 设计规范](04-规范/前端UI设计规范.md)
- [文档维护约定](04-规范/文档维护约定.md)
- [Dashboard 数据流与状态](02-architecture/data-flow.md)
- [Dashboard 改动说明](03-delivery/dashboard-change-summary.md)
- [Dashboard 测试与页面验证报告](03-delivery/dashboard-validation-report.md)

## 维护原则

- 前端实现细节写在 `apps/dashboard/docs/**`。
- API 字段、事件模型和决策契约链接到根目录 `docs/**` 或 `schemas/**`，不在前端文档复制维护。
- 新增页面、路由、store、共享 UI、运行时配置或文案规则时，同步评估是否更新本目录。
