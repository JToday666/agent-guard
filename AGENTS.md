# AGENTS.md

## 适用范围与优先级

- 本文件适用于仓库根目录及所有子目录。
- 指令优先级为：用户当次直接指令 > 本文件 > 代理默认行为。
- 发生指令冲突时，先指出冲突并等待确认，不得自行取舍。
- 仓库或上下文无法确认的不确定点必须先询问。
- 产品、架构、路由、接口、数据模型、鉴权边界、验证范围等重要分岔决策，必须先向用户确认后实施。

## 修改边界

- 可修改范围限于当前任务直接相关的模块与文件；涉及任务范围之外的模块、根配置文件（如 `AGENTS.md`、`package.json`、`pnpm-workspace.yaml`、`pyproject.toml`、锁文件等）或跨模块接口契约时，先向用户确认后实施。
- 谨慎修改：`docs/**` 中与当前任务直接相关的段落。
- 只做当前任务所需的最小改动；不得顺手重构、迁移、重命名或修复无关历史问题。
- 不得回滚、覆盖或删除用户未要求处理的未提交修改。
- 个人工作偏好（如特定模块的默认修改范围）不写入本文件，放在各自代理的用户级配置中维护。

## 实现规则

- 优先最小充分改动，兼顾健壮性、可读性和精简性。
- 仅在确实减少总代码量、重复和维护成本时抽取公共逻辑；否则保留局部实现。
- 删除代码前必须用 `rg` 搜索确认当前无引用。
- 文件名、目录名、路由名、模块名和环境变量名以仓库真实文件及当前文档约束为准。
- 修改 `apps/dashboard/**` 的页面、共享组件、样式或用户可见文案前，必须完整阅读 `docs/04_apps/dashboard_ui_spec.md`。
- 前端命名、组件组织、UI 状态、响应式、可访问性和安全边界以 Dashboard UI 规范、仓库现有实现及相关文档为准；不得引用仓库中不存在的其他 UI 规范文件。

## 命令与工具规范

- 文件发现优先使用 `rg --files`。
- 文本搜索优先使用 `rg`。
- Python 使用 `uv run ...` 和 Python 3.12；不要使用裸 `python`、`pip` 或 `pytest`。
- 前端只使用 `pnpm`；不要使用 `npm`、`yarn` 或 `bun`。
- 依赖安装、卸载、升级或锁文件重算属于敏感操作；仅在用户明确要求或当前任务确实需要时执行。
- 涉及本地前端 env 时，使用 `git check-ignore -v` 确认 `.env.local`、`.env.*.local` 已被忽略。

## Dashboard 前端修改后的检查流程

- Dashboard 使用 Vue 3、TypeScript 和 SCSS。完成一组修改后再执行检查，不要在每个中间编辑步骤后执行。
- 对本次实际修改或新增的 `.vue`、`.ts`、`.scss` 文件运行：

  ```bash
  pnpm --filter @agentguard/dashboard exec prettier --write <files>
  ```

- 对本次实际修改或新增的 `.vue`、`.ts` 文件运行：

  ```bash
  pnpm --filter @agentguard/dashboard exec eslint --fix <files>
  ```

- 修改 `.vue` 或 `.ts` 后运行：

  ```bash
  pnpm --filter @agentguard/dashboard typecheck
  ```

  这是项目级检查，用于覆盖跨文件类型关系。

- 涉及 `apps/dashboard/**` 代码变更时，完成格式化和 ESLint 检查后优先运行：

  ```bash
  pnpm --filter @agentguard/dashboard typecheck
  pnpm --filter @agentguard/dashboard build
  ```

- 如果当前 Dashboard 的 Git 改动都属于本次任务，可运行 `pnpm --filter @agentguard/dashboard check:changed` 自动收集并处理修改文件；工作区含有用户既有改动时，优先使用本次实际修改的显式文件列表。
- 不要为了格式化修改无关的 Dashboard 文件。工作区已有的用户修改属于用户所有，优先使用本次实际修改的文件列表，不要直接格式化全部 `git diff`。
- 仅涉及前端时，不主动运行后端测试；其他测试只运行与当前改动直接相关的最小充分范围。
- 提交前或用户要求全量验证时运行 `pnpm --filter @agentguard/dashboard check`；SCSS 语法由 Sass/Vite 在构建或开发编译时验证。

## 前端与鉴权

- 用户可见页面与共享 UI 禁止写入平台故事、视觉策略、Mock/Coming Soon、架构解释、布局说明、工作区理念、使用建议和开发注释。
- 新增或修改用户可见文案时，必须考虑文本长度差异，避免挤压、重叠和横向溢出。
- 当前用户可见文案使用中文。
- Dashboard 不做用户登录，不保存长期 token，不生成 launch code，不负责启动浏览器。
- 前端只处理 browser session、CSRF token 和 approval nonce；长期凭证不得进入前端代码、前端 env、持久化存储或日志。

## 文档、编码与输出

- 文档修改必须聚焦当前任务，不改无关结构、验收口径或历史内容。
- 根目录 `docs/**` 只补充与当前任务直接相关的跨端事实、接口契约、阶段边界和必要简述；鉴权细节优先沿用仓库已有的鉴权文档，不在本文件重复展开。
- 新增或修改文本文件使用 UTF-8 无 BOM、LF 行尾；不得出现中文乱码。
- 默认跳过依赖、构建、缓存和产物目录：`node_modules/`、`.venv/`、`.uv-cache/`、`dist/`、`dist-ssr/`、`.vite/`、`*.tsbuildinfo`。
- 历史编码异常只在当前任务直接相关且已确认时处理。
- 输出默认使用中文，表达直接、明确、低歧义。
