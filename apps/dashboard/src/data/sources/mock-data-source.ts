import type {
  ApprovalRequest,
  AuditIntegrity,
  EvalMetrics,
  EvaluationSummary,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceGraph,
  TraceDetail,
} from "../../types/dashboard";
import type {
  DashboardDataSource,
  EventFilters,
} from "./dashboard-data-source";
import {
  approvals as fixtureApprovals,
  auditEvents as fixtureEvents,
} from "./mock-data.ts";
import { deriveMetrics } from "../dashboard/metrics.ts";
import { maskSensitiveText } from "../../utils/data-redaction.ts";
import { formatRuleListForDisplay } from "../../utils/rule-display.ts";

function wait(delayMs: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, delayMs));
}

export class MockDashboardDataSource implements DashboardDataSource {
  private readonly delayMs: number;
  private approvals = fixtureApprovals.map((approval) => ({
    ...approval,
    resource: maskSensitiveText(approval.resource),
    agentAction: maskSensitiveText(approval.agentAction),
    approvalNonce: `mock_${approval.id}`,
    expiresAt:
      approval.expiresAt ?? new Date(Date.now() + 15 * 60_000).toISOString(),
  }));

  constructor(delayMs: number) {
    this.delayMs = delayMs;
  }

  async getEvents(filters: EventFilters = {}) {
    await wait(this.delayMs);
    return fixtureEvents
      .filter((event) => !filters.traceId || event.traceId === filters.traceId)
      .filter((event) => !filters.caseId || event.caseId === filters.caseId)
      .filter((event) => !filters.runtime || event.runtime === filters.runtime)
      .filter(
        (event) => !filters.decision || event.decision === filters.decision,
      )
      .map((event) => ({
        ...event,
        resource: maskSensitiveText(event.resource),
        resourceTargets: event.resourceTargets.map(maskSensitiveText),
        agentAction: event.agentAction
          ? maskSensitiveText(event.agentAction)
          : null,
        raw: event,
      }));
  }

  async getMetrics(): Promise<EvalMetrics> {
    await wait(this.delayMs);
    const metrics = deriveMetrics(
      fixtureEvents.map((event) => ({
        ...event,
        latencyMs: event.latencyMs ?? null,
      })),
    );
    return { ...metrics, fpr: 0.016, fnr: 0.048 };
  }

  async getPendingApprovals() {
    await wait(this.delayMs);
    return this.approvals
      .filter((approval) => approval.status === "pending")
      .map((approval) => ({ ...approval }));
  }

  async resolveApproval(
    approval: ApprovalRequest,
    decision: "allow_once" | "deny",
  ) {
    await wait(this.delayMs);
    const target = this.approvals.find((item) => item.id === approval.id);
    if (!target || target.status !== "pending")
      throw new Error("审批已处理或不存在");
    target.status = decision === "allow_once" ? "allowed" : "denied";
    target.resolvedAt = new Date().toISOString();
    return { approvalId: target.id, status: "resolved", decision } as const;
  }

  async getHealth() {
    await wait(this.delayMs);
    return {
      api: "online" as const,
      database: "online" as const,
      checkedAt: new Date().toISOString(),
    };
  }

  async getEvaluation(metrics: EvalMetrics): Promise<EvaluationSummary> {
    return {
      asrBefore: 0.732,
      asrAfter: 0.048,
      blockRate: metrics.blockRate,
      fpr: metrics.fpr,
      fnr: metrics.fnr,
      averageLatencyMs: metrics.averageLatencyMs,
    };
  }

  async getTraceDetail(traceId: string): Promise<TraceDetail> {
    await wait(this.delayMs);
    const events = (await this.getEvents({ traceId })).map((event) => ({
      ...event,
    }));
    return {
      id: traceId,
      events,
      approvals: this.approvals
        .filter((approval) => approval.traceId === traceId)
        .map((approval) => ({ ...approval })),
      metrics: deriveMetrics(
        events.map((event) => ({
          ...event,
          latencyMs: event.latencyMs ?? null,
        })),
      ),
      loadedAt: new Date().toISOString(),
    };
  }

  async getCurrentPolicy(): Promise<PolicySummary> {
    await wait(this.delayMs);
    return {
      bundleId: "default",
      version: "p1",
      revision: 2,
      updatedAt: "2026-06-07T11:50:00+08:00",
      updatedBy: "dashboard",
      disabledRuleCount: 0,
      ruleOverrideCount: 1,
      toolProfileCount: 5,
    };
  }

  async getPolicyHistory(): Promise<PolicyHistoryEntry[]> {
    await wait(this.delayMs);
    return [
      {
        revision: 2,
        updatedAt: "2026-06-07T11:50:00+08:00",
        updatedBy: "dashboard",
        bundleId: "default",
        version: "p1",
      },
      {
        revision: 1,
        updatedAt: "2026-06-07T10:00:00+08:00",
        updatedBy: "system",
        bundleId: "default",
        version: "p0",
      },
    ];
  }

  async getAuditIntegrity(): Promise<AuditIntegrity> {
    await wait(this.delayMs);
    return {
      valid: true,
      eventCount: fixtureEvents.length,
      headHash: "a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
      firstBrokenAuditId: null,
    };
  }

  async getTraceProvenance(traceId: string): Promise<ProvenanceGraph> {
    await wait(this.delayMs);
    const events = fixtureEvents
      .filter((event) => event.traceId === traceId)
      .sort(
        (left, right) =>
          Date.parse(left.occurredAt) - Date.parse(right.occurredAt),
      );
    const firstEvent = events[0];
    if (!firstEvent) return { traceId, nodes: [], edges: [] };
    const lastEvent = events.at(-1)!;
    const approval = firstEvent.approvalId
      ? this.approvals.find((item) => item.id === firstEvent.approvalId)
      : undefined;
    const ruleSummary = firstEvent.ruleHits.length
      ? formatRuleListForDisplay(firstEvent.ruleHits)
      : "未命中阻断规则";
    const outcomeLabel =
      firstEvent.decision === "ask"
        ? "等待人工审批"
        : firstEvent.blocked
          ? "已阻断"
          : "允许执行";

    const nodes = [
      {
        nodeId: `${traceId}:task`,
        traceId,
        kind: "audit",
        refId: `task:${firstEvent.caseId ?? traceId}`,
        label: firstEvent.userTask ?? "用户任务",
        timestamp: firstEvent.occurredAt,
        metadata: {
          lane: "任务",
          source: "mock",
          summary: firstEvent.caseId ?? traceId,
          type: "user_task",
        },
      },
      {
        nodeId: `${traceId}:context`,
        traceId,
        kind: "config_audit",
        refId: `context:${firstEvent.id}`,
        label:
          firstEvent.attackType === "benign"
            ? "任务上下文校验"
            : "外部上下文进入任务",
        timestamp: firstEvent.occurredAt,
        metadata: {
          lane: "上下文",
          source: "mock",
          summary:
            firstEvent.attackType === "benign"
              ? "未发现异常指令"
              : "发现跨任务或外部输入风险",
          type: "context_check",
        },
      },
      {
        nodeId: `${traceId}:action`,
        traceId,
        kind: "event",
        refId: `action:${firstEvent.id}`,
        label: maskSensitiveText(firstEvent.agentAction ?? firstEvent.tool),
        timestamp: firstEvent.occurredAt,
        metadata: {
          lane: "Agent 行为",
          source: "mock",
          summary: firstEvent.tool,
          tool: firstEvent.tool,
        },
      },
      {
        nodeId: `${traceId}:resource`,
        traceId,
        kind: "audit",
        refId: `resource:${firstEvent.id}`,
        label: maskSensitiveText(firstEvent.resource),
        timestamp: firstEvent.occurredAt,
        metadata: {
          lane: "目标资源",
          source: "mock",
          summary: `${firstEvent.resourceTargets.length} 个目标`,
          type: "resource_target",
        },
      },
      ...events.map((event) => ({
        nodeId: `${traceId}:event:${event.id}`,
        traceId,
        kind: "event",
        refId: `event:${event.id}`,
        label: `${event.tool} / ${maskSensitiveText(event.resource)}`,
        timestamp: event.occurredAt,
        metadata: {
          lane: "审计事件",
          source: "mock",
          decision: event.decision,
          riskScore: event.riskScore,
          summary: event.reason,
        },
      })),
      {
        nodeId: `${traceId}:policy`,
        traceId,
        kind: "decision",
        refId: `policy:${firstEvent.id}`,
        label: ruleSummary,
        timestamp: firstEvent.occurredAt,
        metadata: {
          lane: "规则判断",
          source: "mock",
          ruleHits: firstEvent.ruleHits,
          summary: firstEvent.reason,
        },
      },
      {
        nodeId: `${traceId}:critic`,
        traceId,
        kind: "action_critic",
        refId: `critic:${firstEvent.id}`,
        label: firstEvent.riskScore >= 50 ? "需要人工或阻断保护" : "风险可接受",
        timestamp: firstEvent.occurredAt,
        metadata: {
          lane: "二次审查",
          riskScore: firstEvent.riskScore,
          source: "mock",
          summary: `风险 ${firstEvent.riskScore}`,
        },
      },
      ...(approval
        ? [
            {
              nodeId: `${traceId}:approval`,
              traceId,
              kind: "action_critic",
              refId: `approval:${approval.id}`,
              label: approval.status === "pending" ? "等待审批" : "审批已处理",
              timestamp: approval.createdAt,
              metadata: {
                lane: "人工审批",
                source: "mock",
                status: approval.status,
                summary: approval.consequence,
              },
            },
          ]
        : []),
      {
        nodeId: `${traceId}:outcome`,
        traceId,
        kind: "decision",
        refId: `outcome:${firstEvent.id}`,
        label: outcomeLabel,
        timestamp: lastEvent.occurredAt,
        metadata: {
          lane: "最终结果",
          source: "mock",
          blocked: firstEvent.blocked,
          decision: firstEvent.decision,
          summary: firstEvent.blocked ? "动作未直接放行" : "动作已继续执行",
        },
      },
    ];

    const eventEdges = events.map((event, index) => ({
      edgeId: `${traceId}:edge:event:${event.id}`,
      traceId,
      sourceNodeId:
        index === 0
          ? `${traceId}:resource`
          : `${traceId}:event:${events[index - 1]!.id}`,
      targetNodeId: `${traceId}:event:${event.id}`,
      relation: index === 0 ? "生成审计" : "下一事件",
      timestamp: event.occurredAt,
      metadata: { source: "mock" },
    }));

    return {
      traceId,
      nodes,
      edges: [
        {
          edgeId: `${traceId}:edge:task-action`,
          traceId,
          sourceNodeId: `${traceId}:task`,
          targetNodeId: `${traceId}:context`,
          relation: "建立上下文",
          timestamp: firstEvent.occurredAt,
          metadata: { source: "mock" },
        },
        {
          edgeId: `${traceId}:edge:context-action`,
          traceId,
          sourceNodeId: `${traceId}:context`,
          targetNodeId: `${traceId}:action`,
          relation: "触发行为",
          timestamp: firstEvent.occurredAt,
          metadata: { source: "mock" },
        },
        {
          edgeId: `${traceId}:edge:action-resource`,
          traceId,
          sourceNodeId: `${traceId}:action`,
          targetNodeId: `${traceId}:resource`,
          relation: "访问目标",
          timestamp: firstEvent.occurredAt,
          metadata: { source: "mock" },
        },
        ...eventEdges,
        {
          edgeId: `${traceId}:edge:event-policy`,
          traceId,
          sourceNodeId: `${traceId}:event:${lastEvent.id}`,
          targetNodeId: `${traceId}:policy`,
          relation: "规则判断",
          timestamp: firstEvent.occurredAt,
          metadata: { source: "mock" },
        },
        {
          edgeId: `${traceId}:edge:policy-critic`,
          traceId,
          sourceNodeId: `${traceId}:policy`,
          targetNodeId: `${traceId}:critic`,
          relation: "风险复核",
          timestamp: firstEvent.occurredAt,
          metadata: { source: "mock" },
        },
        ...(approval
          ? [
              {
                edgeId: `${traceId}:edge:critic-approval`,
                traceId,
                sourceNodeId: `${traceId}:critic`,
                targetNodeId: `${traceId}:approval`,
                relation: "请求审批",
                timestamp: approval.createdAt,
                metadata: { source: "mock" },
              },
              {
                edgeId: `${traceId}:edge:approval-outcome`,
                traceId,
                sourceNodeId: `${traceId}:approval`,
                targetNodeId: `${traceId}:outcome`,
                relation: "形成结果",
                timestamp: approval.resolvedAt ?? approval.createdAt,
                metadata: { source: "mock" },
              },
            ]
          : [
              {
                edgeId: `${traceId}:edge:critic-outcome`,
                traceId,
                sourceNodeId: `${traceId}:critic`,
                targetNodeId: `${traceId}:outcome`,
                relation: "形成结果",
                timestamp: firstEvent.occurredAt,
                metadata: { source: "mock" },
              },
            ]),
      ],
    };
  }
}
