import { defineStore } from "pinia";
import { computed, ref } from "vue";

import { dashboardEnv } from "../config/dashboard-env";
import { mergeApprovalsWithAuditEvidence } from "../data/approvals/evidence";
import { dashboardDataSource } from "../data/sources/index";
import { deriveMetrics, groupDecisionTrend } from "../data/dashboard/metrics";
import {
  buildInvestigationIndex,
  buildTraceSummary,
} from "../data/investigations";
import {
  getRefreshFailureStatus,
  shouldEnterInitialLoading,
} from "../data/dashboard/refresh-state";
import {
  hasSameEventWindow,
  hasSameEvaluation,
  hasSameMetrics,
  reconcileApprovals,
} from "../data/dashboard/snapshot";
import type {
  AdapterStatus,
  ApprovalRequest,
  AuditIntegrity,
  AuditEventRow,
  ConfigAuditFindingRecord,
  DataStatus,
  EvalMetrics,
  EvaluationSummary,
  HealthStatus,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceGraph,
  TraceDetail,
  TraceSummary,
} from "../types/dashboard";
import {
  getAuthErrorMessage,
  isSessionAuthError,
} from "../utils/auth-error-messages";
import { useAuthStore } from "./authStore";

const emptyMetrics: EvalMetrics = {
  eventCount: 0,
  allowCount: 0,
  denyCount: 0,
  askCount: 0,
  blockedCount: 0,
  blockRate: null,
  fpr: null,
  fnr: null,
  averageLatencyMs: null,
};

const emptyEvaluation: EvaluationSummary = {
  runId: null,
  runAt: null,
  datasetId: null,
  datasetVersion: null,
  datasetLabel: "未提供",
  asrBefore: null,
  asrAfter: null,
  perAttack: [],
  cases: [],
  blockRate: null,
  fpr: null,
  fnr: null,
  averageLatencyMs: null,
};

const unknownOpenClawStatus: AdapterStatus = {
  status: "unknown",
  loaded: false,
  hookCount: null,
  expectedHookCount: 16,
  hookCoverage: null,
  lastVerifiedAt: null,
  lastHeartbeatAt: null,
  error: null,
  source: null,
  runtime: null,
  runtimeId: null,
  agentId: null,
  pluginVersion: null,
  runtimeVersion: null,
  capabilities: {},
  hooks: [],
  failClosedStages: [],
};

const POLL_INTERVAL_MS = 10_000;

function applyLatestPolicyHistory(
  summary: PolicySummary,
  history: PolicyHistoryEntry[],
): PolicySummary {
  const latest = history[0];
  if (!latest) return summary;
  return {
    ...summary,
    revision: latest.revision,
    updatedAt: latest.updatedAt,
    updatedBy: latest.updatedBy,
  };
}

export const useDashboardStore = defineStore("dashboard", () => {
  const events = ref<AuditEventRow[]>([]);
  const approvals = ref<ApprovalRequest[]>([]);
  const metrics = ref<EvalMetrics>({ ...emptyMetrics });
  const evaluation = ref<EvaluationSummary>({ ...emptyEvaluation });
  const evaluationError = ref<string | null>(null);
  const configAuditFindings = ref<ConfigAuditFindingRecord[]>([]);
  const configAuditError = ref<string | null>(null);
  const openclawStatus = ref<AdapterStatus>({ ...unknownOpenClawStatus });
  const openclawStatusError = ref<string | null>(null);
  const traceDetails = ref<Record<string, TraceDetail>>({});
  const traceDetailErrors = ref<Record<string, string>>({});
  const traceDetailLoadingId = ref<string | null>(null);
  const policySummary = ref<PolicySummary | null>(null);
  const policyHistory = ref<PolicyHistoryEntry[]>([]);
  const policyError = ref<string | null>(null);
  const auditIntegrity = ref<AuditIntegrity | null>(null);
  const provenanceByTrace = ref<Record<string, ProvenanceGraph>>({});
  const provenanceErrors = ref<Record<string, string>>({});
  const provenanceLoadingIds = new Set<string>();
  const health = ref<HealthStatus>({
    api: "unknown",
    database: "unknown",
    checkedAt: null,
  });
  const status = ref<DataStatus>("idle");
  const error = ref<string | null>(null);
  const lastUpdatedAt = ref<string | null>(null);
  const isRefreshing = ref(false);
  const submittingApprovalId = ref<string | null>(null);
  let pollTimer: number | null = null;
  let activeController: AbortController | null = null;
  let activeRefresh: Promise<void> | null = null;
  let hasCompletedInitialLoad = false;
  let pollingActive = false;
  let visibilityHandler: (() => void) | null = null;

  const pendingCount = computed(
    () => approvals.value.filter((item) => item.status === "pending").length,
  );
  const decisionTrend = computed(() => groupDecisionTrend(events.value));
  const investigationIndex = computed(() =>
    buildInvestigationIndex(events.value),
  );

  function mapCounts(counts: Map<string, number>) {
    return [...counts.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value);
  }

  const attackDistribution = computed(() => {
    const counts = new Map<string, number>();
    for (const event of investigationIndex.value.latestEvents) {
      const key =
        event.attackType ||
        (event.caseId?.startsWith("BENIGN") ? "benign" : "unknown");
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return mapCounts(counts);
  });
  const ruleDistribution = computed(() => {
    const counts = new Map<string, number>();
    for (const event of investigationIndex.value.latestEvents) {
      for (const rule of event.ruleHits) {
        counts.set(rule, (counts.get(rule) ?? 0) + 1);
      }
    }
    return mapCounts(counts).slice(0, 6);
  });
  const traces = computed<TraceSummary[]>(() =>
    [...investigationIndex.value.byTrace.entries()]
      .map(([id, rows]) => buildTraceSummary(id, rows)!)
      .sort(
        (left, right) =>
          Date.parse(right.lastEventAt) - Date.parse(left.lastEventAt),
      ),
  );

  async function performRefresh(): Promise<void> {
    const controller = new AbortController();
    activeController = controller;
    if (shouldEnterInitialLoading(status.value)) status.value = "loading";

    const results = await Promise.allSettled([
      dashboardDataSource.getEvents({}, controller.signal),
      dashboardDataSource.getMetrics({}, controller.signal),
      dashboardDataSource.getPendingApprovals(controller.signal),
      dashboardDataSource.getHealth(controller.signal),
      dashboardDataSource.getCurrentPolicy(controller.signal),
      dashboardDataSource.getPolicyHistory(controller.signal),
    ] as const);

    const [
      eventsResult,
      metricsResult,
      approvalsResult,
      healthResult,
      policyResult,
      policyHistoryResult,
    ] = results;
    let visibleEvents = events.value;
    if (
      eventsResult.status === "fulfilled" &&
      !hasSameEventWindow(events.value, eventsResult.value)
    ) {
      events.value = eventsResult.value;
    }
    if (eventsResult.status === "fulfilled") visibleEvents = eventsResult.value;
    if (metricsResult.status === "fulfilled") {
      if (!hasSameMetrics(metrics.value, metricsResult.value)) {
        metrics.value = metricsResult.value;
      }
    } else if (eventsResult.status === "fulfilled") {
      const derivedMetrics = deriveMetrics(events.value);
      if (!hasSameMetrics(metrics.value, derivedMetrics)) {
        metrics.value = derivedMetrics;
      }
    }
    if (approvalsResult.status === "fulfilled") {
      const enrichedApprovals = mergeApprovalsWithAuditEvidence(
        approvalsResult.value,
        visibleEvents,
      );
      approvals.value = reconcileApprovals(approvals.value, enrichedApprovals);
    }
    if (healthResult.status === "fulfilled") health.value = healthResult.value;
    if (policyHistoryResult.status === "fulfilled") {
      policyHistory.value = policyHistoryResult.value;
    }
    if (policyResult.status === "fulfilled") {
      const history =
        policyHistoryResult.status === "fulfilled"
          ? policyHistoryResult.value
          : policyHistory.value;
      policySummary.value = applyLatestPolicyHistory(
        policyResult.value,
        history,
      );
      policyError.value = null;
    } else {
      policyError.value =
        policyResult.reason instanceof Error
          ? policyResult.reason.message
          : "策略数据加载失败";
    }

    const secondaryResults = await Promise.allSettled([
      dashboardDataSource.getAuditIntegrity(controller.signal),
      dashboardDataSource.getEvaluation(metrics.value, controller.signal),
      dashboardDataSource.getConfigAuditFindings(
        { limit: 20 },
        controller.signal,
      ),
      dashboardDataSource.getAdapterStatus("openclaw", controller.signal),
    ] as const);

    const [
      auditIntegrityResult,
      evaluationResult,
      configFindingsResult,
      openclawStatusResult,
    ] = secondaryResults;

    if (auditIntegrityResult.status === "fulfilled") {
      auditIntegrity.value = auditIntegrityResult.value;
    }
    if (evaluationResult.status === "fulfilled") {
      if (!hasSameEvaluation(evaluation.value, evaluationResult.value)) {
        evaluation.value = evaluationResult.value;
      }
      evaluationError.value = null;
    } else {
      evaluationError.value =
        evaluationResult.reason instanceof Error
          ? evaluationResult.reason.message
          : "评测结果加载失败";
    }
    if (configFindingsResult.status === "fulfilled") {
      configAuditFindings.value = configFindingsResult.value;
      configAuditError.value = null;
    } else {
      configAuditError.value =
        configFindingsResult.reason instanceof Error
          ? configFindingsResult.reason.message
          : "配置审计发现项加载失败";
    }
    if (openclawStatusResult.status === "fulfilled") {
      openclawStatus.value = openclawStatusResult.value;
      openclawStatusError.value = null;
    } else {
      openclawStatusError.value =
        openclawStatusResult.reason instanceof Error
          ? openclawStatusResult.reason.message
          : "OpenClaw 状态加载失败";
    }

    const secondaryFailures = secondaryResults.filter(
      (result) => result.status === "rejected",
    ) as PromiseRejectedResult[];
    const secondarySessionFailure = secondaryFailures.find((failure) =>
      isSessionAuthError(failure.reason),
    );
    if (secondarySessionFailure) {
      useAuthStore().invalidateSession(
        getAuthErrorMessage(secondarySessionFailure.reason),
      );
      stopPolling();
    }

    const failures = [
      eventsResult,
      metricsResult,
      approvalsResult,
      healthResult,
    ].filter(
      (result) => result.status === "rejected",
    ) as PromiseRejectedResult[];
    if (failures.length) {
      const sessionFailure = failures.find((failure) =>
        isSessionAuthError(failure.reason),
      );
      if (sessionFailure) {
        useAuthStore().invalidateSession(
          getAuthErrorMessage(sessionFailure.reason),
        );
        stopPolling();
      }
      status.value = getRefreshFailureStatus(hasCompletedInitialLoad);
      error.value =
        failures[0].reason instanceof Error
          ? failures[0].reason.message
          : "数据加载失败";
    } else {
      hasCompletedInitialLoad = true;
      status.value = "ready";
      error.value = null;
      lastUpdatedAt.value = new Date().toISOString();
    }
    if (activeController === controller) activeController = null;
  }

  function clearPollTimer(): void {
    if (pollTimer !== null) window.clearTimeout(pollTimer);
    pollTimer = null;
  }

  function scheduleNextPoll(): void {
    clearPollTimer();
    if (!pollingActive || document.visibilityState !== "visible") return;
    pollTimer = window.setTimeout(() => {
      pollTimer = null;
      void refresh();
    }, POLL_INTERVAL_MS);
  }

  function refresh(): Promise<void> {
    if (activeRefresh) return activeRefresh;
    if (pollingActive) clearPollTimer();
    isRefreshing.value = true;
    const refreshTask = performRefresh().finally(() => {
      if (activeRefresh === refreshTask) activeRefresh = null;
      isRefreshing.value = false;
      scheduleNextPoll();
    });
    activeRefresh = refreshTask;
    return refreshTask;
  }

  async function resolveApproval(
    approval: ApprovalRequest,
    decision: "allow_once" | "deny",
  ) {
    if (submittingApprovalId.value) return;
    const auth = useAuthStore();
    submittingApprovalId.value = approval.id;
    error.value = null;
    try {
      await dashboardDataSource.resolveApproval(
        approval,
        decision,
        auth.csrfToken,
      );
      await refresh();
    } catch (reason) {
      error.value = reason instanceof Error ? reason.message : "审批提交失败";
      throw reason;
    } finally {
      submittingApprovalId.value = null;
    }
  }

  async function loadTraceDetail(traceId: string): Promise<void> {
    if (!traceId || traceDetailLoadingId.value === traceId) return;
    traceDetailLoadingId.value = traceId;
    traceDetailErrors.value = { ...traceDetailErrors.value, [traceId]: "" };
    try {
      const detail = await dashboardDataSource.getTraceDetail(traceId);
      traceDetails.value = { ...traceDetails.value, [traceId]: detail };
    } catch (reason) {
      if (isSessionAuthError(reason)) {
        useAuthStore().invalidateSession(getAuthErrorMessage(reason));
        stopPolling();
      }
      traceDetailErrors.value = {
        ...traceDetailErrors.value,
        [traceId]:
          reason instanceof Error ? reason.message : "证据链数据加载失败",
      };
    } finally {
      if (traceDetailLoadingId.value === traceId)
        traceDetailLoadingId.value = null;
    }
  }

  function startPolling(): void {
    if (pollingActive) return;
    pollingActive = true;
    visibilityHandler = () => {
      clearPollTimer();
      if (document.visibilityState === "visible") void refresh();
    };
    document.addEventListener("visibilitychange", visibilityHandler);
    scheduleNextPoll();
  }

  function stopPolling(): void {
    pollingActive = false;
    clearPollTimer();
    if (visibilityHandler)
      document.removeEventListener("visibilitychange", visibilityHandler);
    visibilityHandler = null;
    activeController?.abort();
  }

  async function loadTraceProvenance(traceId: string): Promise<void> {
    if (
      !traceId ||
      provenanceByTrace.value[traceId] ||
      provenanceLoadingIds.has(traceId)
    )
      return;
    provenanceLoadingIds.add(traceId);
    try {
      const graph = await dashboardDataSource.getTraceProvenance(traceId);
      provenanceByTrace.value = {
        ...provenanceByTrace.value,
        [traceId]: graph,
      };
    } catch (reason) {
      provenanceErrors.value = {
        ...provenanceErrors.value,
        [traceId]: reason instanceof Error ? reason.message : "溯源图加载失败",
      };
    } finally {
      provenanceLoadingIds.delete(traceId);
    }
  }

  return {
    events,
    approvals,
    metrics,
    evaluation,
    evaluationError,
    configAuditFindings,
    configAuditError,
    openclawStatus,
    openclawStatusError,
    traceDetails,
    traceDetailErrors,
    traceDetailLoadingId,
    policySummary,
    policyHistory,
    policyError,
    auditIntegrity,
    provenanceByTrace,
    provenanceErrors,
    health,
    status,
    error,
    lastUpdatedAt,
    isRefreshing,
    submittingApprovalId,
    pendingCount,
    decisionTrend,
    investigationIndex,
    attackDistribution,
    traces,
    ruleDistribution,
    dataSourceMode: dashboardEnv.dataSource,
    refresh,
    loadTraceDetail,
    loadTraceProvenance,
    resolveApproval,
    startPolling,
    stopPolling,
  };
});
