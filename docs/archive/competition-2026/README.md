# Competition 2026 archive

本目录保存 2026 年竞赛/答辩阶段的历史要求与精选证据，不是当前产品、
安装、正式效果或生产就绪入口。

## 归档集合

### Competition requirements

2026-08-28 从 `dev@892b4a485211092dfe9f88cfb1594aa21e6f5f53` 的
`docs/00_requirements/` 迁入：

- [原始命题](requirements/命题.pdf)
- [命题解读](requirements/命题一_题目解读总结.md)
- [历史要求追踪矩阵](requirements/requirement_traceability_matrix.md)

追踪矩阵记录当时的命题映射和验收判断，不是当前产品契约或开发路线。

### Demo evidence

- 来源分支：`demo/v2-rollback-baseline`
- 来源提交：`9cfe2f09450d0434dd1bb6da2fac5fad42184ebe`
- 归档日期：2026-08-24
- 可复现性：`historical-ephemeral-environment`

报告依赖当时的临时本地环境、ignored `.openclaw-dev` 工具和临时结果目录。
原始运行输出不在 Git 中；仓库只保留精选报告和样本。这些文件不能替代干净
clone 验收、真实 Provider 评测或当前产品证据。

[`manifest.json`](manifest.json) 分别记录两类来源和所有保留文件的 SHA-256。

## 当前入口

- [AttackBench 攻击样本与评测](../../05_redteam/attackbench.md)
- [Productization Alpha Status](../../06_delivery/productization_alpha_status.md)
- [安装、升级和故障排查](../../06_delivery/install_upgrade_troubleshooting.md)
- [干净 clone 最小示例](../../../examples/README.md)
