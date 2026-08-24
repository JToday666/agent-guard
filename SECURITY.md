# Security Policy

AgentGuard 处理运行时动作、审批、凭证和审计证据。请把可能绕过执行前门禁、伪造审计链、越权审批、泄露凭证或跨租户读取数据的问题视为安全问题。

## 支持范围

| 版本/分支 | 状态 |
| --- | --- |
| `dev`、`main` 的最新版本 | 接受安全报告；修复进入仍受支持的最新版本 |
| `0.1.0-beta.1` | Beta；仅在最新源码仍受影响时评估回补 |
| 历史竞赛、演示或归档提交 | 不单独维护；用于判断最新产品代码是否受影响 |

仓库目前处于 Productization Alpha，尚不承诺长期支持窗口或生产 SLA。

## 私密报告方式

截至 2026-08-24，本仓库已启用 GitHub Private Vulnerability Reporting；请优先使用 **Security → Advisories → Report a vulnerability** 私密提交。平台状态仍需由维护者定期回读核验。若入口不可见，请不要在公开 Issue、Discussion、PR、日志或演示报告中披露可利用细节、token、真实数据或未修复的 PoC；只提交不含漏洞细节的联系请求，等待维护者建立私密渠道。

报告请尽量包含：

- 受影响的 commit、组件和配置；
- 可重复的最小步骤或经过脱敏的 PoC；
- 预期安全属性与实际行为；
- 影响范围、前置条件和已验证的缓解措施；
- 是否涉及真实凭证或数据。真实秘密只描述类型，不粘贴明文。

维护者会先确认收到报告，再完成复现、严重性判断和修复安排。响应时间取决于项目维护能力，不构成 SLA。修复公开前，请与维护者协调披露时间。

## 安全边界

- Core 的 `allow`、`deny`、`ask` 是策略决定；runtime receipt 才能证明副作用是否实际发生。
- `shadow`、Mock、stub、沙箱 outbox 和演示数据不是生产 enforcement 或效果证据。
- 生产部署必须使用独立 PostgreSQL、非默认凭证、TLS/可信网络、数据库外签名检查点和受控 secret 注入。
- 当前未完成的生产化限制见[Productization Alpha Status](docs/06_delivery/productization_alpha_status.md)与[安装、升级和故障排查](docs/06_delivery/install_upgrade_troubleshooting.md)。

## 非安全问题

普通缺陷、文档问题和功能建议可以使用公开 Issue。请先移除 token、个人信息、数据库内容和本地路径中的敏感信息。
