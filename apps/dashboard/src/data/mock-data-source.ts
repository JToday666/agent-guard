import {
  approvals as fixtureApprovals,
  auditEvents as fixtureEvents,
} from "../mocks/dashboard-data";
import type {
  ApprovalRequest,
  AuditIntegrity,
  EvalMetrics,
  EvaluationSummary,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceGraph,
  TraceDetail,
} from "../types/dashboard";
import type {
  DashboardDataSource,
  EventFilters,
} from "./dashboard-data-source";
import { deriveMetrics } from "./dashboard-metrics";
import { maskSensitiveText } from "../utils/data-redaction";

function wait(delayMs: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, delayMs));
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
    return { traceId, nodes: [], edges: [] };
  }
}
