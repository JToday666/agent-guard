# 演示脚本

## 1. Demo 1：LangGraph 文件泄露攻击

1. 运行无防御 Agent。
2. 输入恶意邮件样本。
3. Agent 尝试读取 `/private/token.txt`。
4. 展示攻击成功。
5. 开启 AgentGuard。
6. 重放相同样本。
7. Core 返回 deny。
8. Dashboard 显示阻断原因。

## 2. Demo 2：工具调用劫持

1. 用户任务是总结邮件。
2. 恶意上下文诱导调用 `send_email`。
3. Core 判断任务不一致和外发风险。
4. 返回 ask 或 deny。
5. Dashboard 显示审批或阻断。

## 3. Demo 3：OpenClaw 真实接入

1. 启动 OpenClaw。
2. 安装 AgentGuard Security Plugin。
3. 发送恶意消息。
4. 触发 `before_tool_call`。
5. Core 返回 deny。
6. Dashboard 显示 OpenClaw runtime 事件。

## 4. Demo 4：指标对比

展示：

- ASR before；
- ASR after；
- Block Rate；
- FPR；
- Latency。
