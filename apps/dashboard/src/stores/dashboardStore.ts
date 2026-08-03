import { defineStore } from "pinia";
import { computed, ref } from "vue";

import { mergeApprovalsWithAuditEvidence } from "../data/approvals/evidence";
import { dashboardDataSource } from "../data/sources/index";
import {
  createAuditWindow,
  groupDecisionTrend,
  selectLogicalPolicyEvaluations,
} from "../data/dashboard/metrics";
import { buildInvestigationIndex, buildTraceSummary } from "../data/investigations";
import {
  hasSameAuditWindow,
  hasSameEvaluationRun,
  reconcileApprovals,
} from "../data/dashboard/snapshot";
import { AUDIT_EVENT_WINDOW_LIMIT } from "../data/sources/dashboard-data-source";
import type {
  AdapterStatus,
  AggregateMetrics,
  ApprovalRequest,
  AuditWindow,
  AuditIntegrity,
  ConfigAuditFindingRecord,
  DataStatus,
  EvaluationRun,
  HealthStatus,
  PolicyHistoryEntry,
  PolicySummary,
  ProvenanceGraph,
  TraceDetail,
  TraceSummary,
} from "../types/dashboard";
import { getAuthErrorMessage, isSessionAuthError } from "../utils/auth-error-messages";
import { getApprovalResolutionFailure } from "../utils/approval-resolution";
import {
  getCachedValue,
  getFreshCacheValue,
  removeCacheValue,
  setBoundedCacheValue,
  type TimedCache,
  unwrapTimedCache,
} from "../utils/bounded-cache";
import {
  getDashboardRefreshResources,
  type DashboardRefreshResource,
  type DashboardRefreshScope,
} from "../utils/dashboard-refresh-scope";
import { useAuthStore } from "./authStore";

const emptyEvaluationRun: EvaluationRun = {
  runId: null,
  runAt: null,
  datasetId: null,
  datasetVersion: null,
  datasetLabel: "未提供",
  asrBefore: null,
  asrAfter: null,
  perAttack: [],
  cases: [],
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
const TRACE_CACHE_MAX_ENTRIES = 8;
const TRACE_DETAIL_TTL_MS = 60_000;
const TRACE_PROVENANCE_TTL_MS = 120_000;

interface ScopeRefreshState {
  error: string | null;
  hasLoaded: boolean;
  status: DataStatus;
  updatedAt: string | null;
}

interface RefreshTask {
  critical: boolean;
  label: string;
  promise: Promise<void>;
  resource: DashboardRefreshResource;
}

export type DashboardRefreshIntent = "initial" | "manual" | "navigation" | "poll" | "visibility";

function createScopeRefreshState(): ScopeRefreshState {
  return {
    error: null,
    hasLoaded: false,
    status: "idle",
    updatedAt: null,
  };
}

function createScopeRefreshStates(): Record<DashboardRefreshScope, ScopeRefreshState> {
  return {
    approvals: createScopeRefreshState(),
    evaluation: createScopeRefreshState(),
    evidence: createScopeRefreshState(),
    investigations: createScopeRefreshState(),
    overview: createScopeRefreshState(),
    system: createScopeRefreshState(),
  };
}

function errorMessage(reason: unknown, fallback: string): string {
  return reason instanceof Error ? reason.message : fallback;
}

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
  const auditWindow = ref<AuditWindow>(
    createAuditWindow([], {
      limit: AUDIT_EVENT_WINDOW_LIMIT,
      hasMore: null,
      source: "legacy_audit_events",
    }),
  );
  const aggregateMetrics = ref<AggregateMetrics | null>(null);
  const aggregateMetricsError = ref<string | null>(null);
  const approvals = ref<ApprovalRequest[]>([]);
  const evaluationRun = ref<EvaluationRun>({ ...emptyEvaluationRun });
  const evaluationRunError = ref<string | null>(null);
  const configAuditFindings = ref<ConfigAuditFindingRecord[]>([]);
  const configAuditError = ref<string | null>(null);
  const openclawStatus = ref<AdapterStatus>({ ...unknownOpenClawStatus });
  const openclawStatusError = ref<string | null>(null);
  const traceDetailCache = ref<TimedCache<TraceDetail>>({});
  const traceDetailErrors = ref<Record<string, string>>({});
  const traceDetailLoadingId = ref<string | null>(null);
  const policySummary = ref<PolicySummary | null>(null);
  const policyHistory = ref<PolicyHistoryEntry[]>([]);
  const policyError = ref<string | null>(null);
  const auditIntegrity = ref<AuditIntegrity | null>(null);
  const auditIntegrityError = ref<string | null>(null);
  const provenanceCache = ref<TimedCache<ProvenanceGraph>>({});
  const provenanceErrors = ref<Record<string, string>>({});
  const provenanceLoadingIds = new Set<string>();
  const health = ref<HealthStatus>({
    api: "unknown",
    database: "unknown",
    checkedAt: null,
  });
  const activeScope = ref<DashboardRefreshScope>("overview");
  const scopeStates = ref(createScopeRefreshStates());
  const activeRefreshScope = ref<DashboardRefreshScope | null>(null);
  const activeRefreshIntent = ref<DashboardRefreshIntent | null>(null);
  const submittingApprovalId = ref<string | null>(null);
  const approvalResolutionError = ref<string | null>(null);
  const approvalResolutionState = ref<"idle" | "submitting" | "succeeded" | "conflict" | "failed">(
    "idle",
  );
  let pollTimer: number | null = null;
  let activeRefresh: {
    controller: AbortController;
    intent: DashboardRefreshIntent;
    promise: Promise<void>;
    scope: DashboardRefreshScope;
  } | null = null;
  const resourceUpdatedAt = new Map<DashboardRefreshResource, number>();
  let pollingActive = false;
  let visibilityHandler: (() => void) | null = null;

  const status = computed(() => scopeStates.value[activeScope.value].status);
  const error = computed(() => scopeStates.value[activeScope.value].error);
  const lastUpdatedAt = computed(() => scopeStates.value[activeScope.value].updatedAt);
  const isRefreshing = computed(() => activeRefreshScope.value === activeScope.value);
  const isManualRefreshing = computed(
    () => isRefreshing.value && activeRefreshIntent.value === "manual",
  );
  const traceDetails = computed(() => unwrapTimedCache(traceDetailCache.value));
  const provenanceByTrace = computed(() => unwrapTimedCache(provenanceCache.value));
  const events = computed(() => auditWindow.value.events);
  const windowMetrics = computed(() => auditWindow.value.metrics);
  const policyEvaluations = computed(
    () => selectLogicalPolicyEvaluations(auditWindow.value.events).events,
  );
  const pendingCount = computed(
    () => approvals.value.filter((item) => item.status === "pending").length,
  );
  const decisionTrend = computed(() => groupDecisionTrend(auditWindow.value.events));
  const investigationIndex = computed(() => buildInvestigationIndex(auditWindow.value.events));

  function mapCounts(counts: Map<string, number>) {
    return [...counts.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value);
  }

  function handleSessionError(reason: unknown): void {
    if (!isSessionAuthError(reason)) return;
    useAuthStore().invalidateSession(getAuthErrorMessage(reason));
    stopPolling();
  }

  async function refreshApprovals(): Promise<void> {
    const pendingApprovals = await dashboardDataSource.getPendingApprovals();
    const enrichedApprovals = mergeApprovalsWithAuditEvidence(
      pendingApprovals,
      auditWindow.value.events,
    );
    approvals.value = reconcileApprovals(approvals.value, enrichedApprovals);
    resourceUpdatedAt.set("approvals", Date.now());
  }

  const attackDistribution = computed(() => {
    const counts = new Map<string, number>();
    for (const event of policyEvaluations.value) {
      const key = event.attackType || (event.caseId?.startsWith("BENIGN") ? "benign" : "unknown");
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return mapCounts(counts);
  });
  const ruleDistribution = computed(() => {
    const counts = new Map<string, number>();
    for (const event of policyEvaluations.value) {
      for (const rule of event.ruleHits) {
        counts.set(rule, (counts.get(rule) ?? 0) + 1);
      }
    }
    return mapCounts(counts).slice(0, 6);
  });
  const traces = computed<TraceSummary[]>(() =>
    [...investigationIndex.value.byTrace.entries()]
      .map(([id, rows]) => buildTraceSummary(id, rows)!)
      .sort((left, right) => Date.parse(right.lastEventAt) - Date.parse(left.lastEventAt)),
  );

  async function performRefresh(
    scope: DashboardRefreshScope,
    controller: AbortController,
    intent: DashboardRefreshIntent,
  ): Promise<void> {
    const requestedResources = getDashboardRefreshResources(scope);
    const forceRefresh = intent === "initial" || intent === "manual" || intent === "visibility";
    const resources = new Set(
      [...requestedResources].filter((resource) => {
        if (forceRefresh) return true;
        const updatedAt = resourceUpdatedAt.get(resource);
        return updatedAt === undefined || Date.now() - updatedAt >= POLL_INTERVAL_MS;
      }),
    );
    const previousState = scopeStates.value[scope];
    if (previousState.status === "idle") {
      scopeStates.value = {
        ...scopeStates.value,
        [scope]: { ...previousState, status: "loading" },
      };
    }

    const auditWindowRequest = resources.has("auditWindow")
      ? dashboardDataSource.getAuditWindow({}, controller.signal)
      : null;
    const policyHistoryRequest = resources.has("policyHistory")
      ? dashboardDataSource.getPolicyHistory(controller.signal)
      : null;
    const tasks: RefreshTask[] = [];

    if (auditWindowRequest) {
      tasks.push({
        critical:
          scope === "overview" ||
          scope === "investigations" ||
          scope === "evidence" ||
          scope === "evaluation",
        label: "审计窗口",
        resource: "auditWindow",
        promise: auditWindowRequest.then((nextWindow) => {
          if (!hasSameAuditWindow(auditWindow.value, nextWindow)) {
            auditWindow.value = nextWindow;
          }
        }),
      });
    }

    if (resources.has("approvals")) {
      tasks.push({
        critical: scope === "approvals",
        label: "审批队列",
        resource: "approvals",
        promise: dashboardDataSource
          .getPendingApprovals(controller.signal)
          .then(async (pendingApprovals) => {
            const visibleEvents = auditWindowRequest
              ? (await auditWindowRequest.catch(() => auditWindow.value)).events
              : auditWindow.value.events;
            const enrichedApprovals = mergeApprovalsWithAuditEvidence(
              pendingApprovals,
              visibleEvents,
            );
            approvals.value = reconcileApprovals(approvals.value, enrichedApprovals);
          }),
      });
    }

    if (resources.has("health")) {
      tasks.push({
        critical: scope === "system",
        label: "服务健康",
        resource: "health",
        promise: dashboardDataSource.getHealth(controller.signal).then((nextHealth) => {
          health.value = nextHealth;
        }),
      });
    }

    if (policyHistoryRequest) {
      tasks.push({
        critical: false,
        label: "策略历史",
        resource: "policyHistory",
        promise: policyHistoryRequest.then((history) => {
          policyHistory.value = history;
        }),
      });
    }

    if (resources.has("policy")) {
      tasks.push({
        critical: false,
        label: "策略摘要",
        resource: "policy",
        promise: dashboardDataSource
          .getCurrentPolicy(controller.signal)
          .then(async (summary) => {
            const history = policyHistoryRequest
              ? await policyHistoryRequest.catch(() => policyHistory.value)
              : policyHistory.value;
            policySummary.value = applyLatestPolicyHistory(summary, history);
            policyError.value = null;
          })
          .catch((reason: unknown) => {
            if (!controller.signal.aborted) {
              policyError.value = errorMessage(reason, "策略数据加载失败");
            }
            throw reason;
          }),
      });
    }

    if (resources.has("auditIntegrity")) {
      tasks.push({
        critical: false,
        label: "审计完整性",
        resource: "auditIntegrity",
        promise: dashboardDataSource
          .getAuditIntegrity(controller.signal)
          .then((integrity) => {
            auditIntegrity.value = integrity;
            auditIntegrityError.value = null;
          })
          .catch((reason: unknown) => {
            if (!controller.signal.aborted) {
              auditIntegrityError.value = errorMessage(reason, "审计完整性加载失败");
            }
            throw reason;
          }),
      });
    }

    if (resources.has("evaluationRun")) {
      tasks.push({
        critical: false,
        label: "安全评测",
        resource: "evaluationRun",
        promise: dashboardDataSource
          .getLatestEvaluationRun(controller.signal)
          .then((nextEvaluation) => {
            if (!hasSameEvaluationRun(evaluationRun.value, nextEvaluation)) {
              evaluationRun.value = nextEvaluation;
            }
            evaluationRunError.value = null;
          })
          .catch((reason: unknown) => {
            if (!controller.signal.aborted) {
              evaluationRunError.value = errorMessage(reason, "评测结果加载失败");
            }
            throw reason;
          }),
      });
    }

    if (resources.has("configAudit")) {
      tasks.push({
        critical: false,
        label: "配置审计",
        resource: "configAudit",
        promise: dashboardDataSource
          .getConfigAuditFindings({ limit: 20 }, controller.signal)
          .then((findings) => {
            configAuditFindings.value = findings;
            configAuditError.value = null;
          })
          .catch((reason: unknown) => {
            if (!controller.signal.aborted) {
              configAuditError.value = errorMessage(reason, "配置审计发现项加载失败");
            }
            throw reason;
          }),
      });
    }

    if (resources.has("adapter")) {
      tasks.push({
        critical: false,
        label: "OpenClaw 适配器",
        resource: "adapter",
        promise: dashboardDataSource
          .getAdapterStatus("openclaw", controller.signal)
          .then((adapterStatus) => {
            openclawStatus.value = adapterStatus;
            openclawStatusError.value = null;
          })
          .catch((reason: unknown) => {
            if (!controller.signal.aborted) {
              openclawStatusError.value = errorMessage(reason, "OpenClaw 状态加载失败");
            }
            throw reason;
          }),
      });
    }

    const results = await Promise.allSettled(tasks.map((task) => task.promise));
    if (controller.signal.aborted) return;

    const refreshedAt = Date.now();
    results.forEach((result, index) => {
      if (result.status === "fulfilled") {
        resourceUpdatedAt.set(tasks[index]!.resource, refreshedAt);
      }
    });

    const failures = results.flatMap((result, index) =>
      result.status === "rejected" ? [{ ...tasks[index]!, reason: result.reason }] : [],
    );
    const sessionFailure = failures.find((failure) => isSessionAuthError(failure.reason));
    if (sessionFailure) handleSessionError(sessionFailure.reason);

    const criticalFailures = failures.filter((failure) => failure.critical);
    const hasFreshPageData = criticalFailures.length === 0;
    const hasLoaded = previousState.hasLoaded || hasFreshPageData;
    const status: DataStatus =
      criticalFailures.length && !previousState.hasLoaded
        ? "error"
        : failures.length
          ? "stale"
          : "ready";
    const failedLabels = [...new Set(failures.map((failure) => failure.label))];
    const error = failedLabels.length
      ? `${failedLabels.join("、")}暂未更新${
          previousState.hasLoaded ? "，当前保留上次成功数据" : ""
        }`
      : null;
    const resourceTimestamps = [...requestedResources].flatMap((resource) => {
      const timestamp = resourceUpdatedAt.get(resource);
      return timestamp === undefined ? [] : [timestamp];
    });
    const scopeUpdatedAt = resourceTimestamps.length
      ? new Date(Math.min(...resourceTimestamps)).toISOString()
      : previousState.updatedAt;

    scopeStates.value = {
      ...scopeStates.value,
      [scope]: {
        error,
        hasLoaded,
        status,
        updatedAt: hasFreshPageData ? scopeUpdatedAt : previousState.updatedAt,
      },
    };
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
      void refresh(undefined, "poll");
    }, POLL_INTERVAL_MS);
  }

  function setActiveScope(scope: DashboardRefreshScope): void {
    if (activeScope.value === scope) return;
    activeScope.value = scope;
    if (activeRefresh && activeRefresh.scope !== scope) {
      activeRefresh.controller.abort();
    }
  }

  function refresh(
    scope = activeScope.value,
    intent: DashboardRefreshIntent = "manual",
  ): Promise<void> {
    setActiveScope(scope);
    if (activeRefresh?.scope === scope) {
      if (intent !== "manual" || activeRefresh.intent === "manual") return activeRefresh.promise;
    }
    if (activeRefresh) activeRefresh.controller.abort();
    if (pollingActive) clearPollTimer();
    const controller = new AbortController();
    activeRefreshScope.value = scope;
    const refreshRecord = {
      controller,
      intent,
      scope,
      promise: Promise.resolve(),
    };
    activeRefreshIntent.value = intent;
    const promise = performRefresh(scope, controller, intent).finally(() => {
      if (activeRefresh === refreshRecord) {
        activeRefresh = null;
        activeRefreshScope.value = null;
        activeRefreshIntent.value = null;
        scheduleNextPoll();
      }
    });
    refreshRecord.promise = promise;
    activeRefresh = refreshRecord;
    return promise;
  }

  async function resolveApproval(approval: ApprovalRequest, decision: "allow_once" | "deny") {
    if (submittingApprovalId.value) return;
    const auth = useAuthStore();
    submittingApprovalId.value = approval.id;
    approvalResolutionError.value = null;
    approvalResolutionState.value = "submitting";
    try {
      const resolution = await dashboardDataSource.resolveApproval(
        approval,
        decision,
        auth.csrfToken,
      );
      approvalResolutionState.value = "succeeded";
      approvals.value = approvals.value.filter((item) => item.id !== approval.id);
      traceDetailCache.value = removeCacheValue(traceDetailCache.value, approval.traceId);
      provenanceCache.value = removeCacheValue(provenanceCache.value, approval.traceId);
      void refreshApprovals().catch(handleSessionError);
      return resolution;
    } catch (reason) {
      handleSessionError(reason);
      const failure = getApprovalResolutionFailure(reason);
      approvalResolutionError.value = failure.message;
      approvalResolutionState.value = failure.kind === "conflict" ? "conflict" : "failed";
      if (failure.shouldRefreshQueue) {
        await refreshApprovals().catch(handleSessionError);
      }
      throw reason;
    } finally {
      submittingApprovalId.value = null;
    }
  }

  async function loadAggregateMetrics(): Promise<void> {
    aggregateMetricsError.value = null;
    try {
      aggregateMetrics.value = await dashboardDataSource.getAggregateMetrics();
    } catch (reason) {
      handleSessionError(reason);
      aggregateMetricsError.value = errorMessage(reason, "历史聚合指标加载失败");
      throw reason;
    }
  }

  async function loadTraceDetail(traceId: string, force = false): Promise<void> {
    if (!traceId || traceDetailLoadingId.value === traceId) return;
    if (!force && getFreshCacheValue(traceDetailCache.value, traceId, TRACE_DETAIL_TTL_MS)) return;
    const cachedDetail = getCachedValue(traceDetailCache.value, traceId);
    traceDetailLoadingId.value = traceId;
    traceDetailErrors.value = { ...traceDetailErrors.value, [traceId]: "" };
    try {
      const detail = await dashboardDataSource.getTraceDetail(traceId);
      traceDetailCache.value = setBoundedCacheValue(
        traceDetailCache.value,
        traceId,
        detail,
        TRACE_CACHE_MAX_ENTRIES,
      );
    } catch (reason) {
      handleSessionError(reason);
      traceDetailErrors.value = {
        ...traceDetailErrors.value,
        [traceId]: cachedDetail
          ? "证据链刷新失败，当前显示上次成功加载的数据"
          : errorMessage(reason, "证据链数据加载失败"),
      };
    } finally {
      if (traceDetailLoadingId.value === traceId) traceDetailLoadingId.value = null;
    }
  }

  function startPolling(): void {
    if (pollingActive) return;
    pollingActive = true;
    visibilityHandler = () => {
      clearPollTimer();
      if (document.visibilityState === "visible") void refresh(undefined, "visibility");
    };
    document.addEventListener("visibilitychange", visibilityHandler);
    scheduleNextPoll();
  }

  function stopPolling(): void {
    pollingActive = false;
    clearPollTimer();
    if (visibilityHandler) document.removeEventListener("visibilitychange", visibilityHandler);
    visibilityHandler = null;
    activeRefresh?.controller.abort();
  }

  async function loadTraceProvenance(traceId: string, force = false): Promise<void> {
    if (!traceId || provenanceLoadingIds.has(traceId)) return;
    if (!force && getFreshCacheValue(provenanceCache.value, traceId, TRACE_PROVENANCE_TTL_MS))
      return;
    const cachedProvenance = getCachedValue(provenanceCache.value, traceId);
    provenanceLoadingIds.add(traceId);
    provenanceErrors.value = { ...provenanceErrors.value, [traceId]: "" };
    try {
      const graph = await dashboardDataSource.getTraceProvenance(traceId);
      provenanceCache.value = setBoundedCacheValue(
        provenanceCache.value,
        traceId,
        graph,
        TRACE_CACHE_MAX_ENTRIES,
      );
    } catch (reason) {
      handleSessionError(reason);
      provenanceErrors.value = {
        ...provenanceErrors.value,
        [traceId]: cachedProvenance
          ? "溯源关系刷新失败，当前显示上次成功加载的数据"
          : errorMessage(reason, "溯源图加载失败"),
      };
    } finally {
      provenanceLoadingIds.delete(traceId);
    }
  }

  return {
    auditWindow,
    windowMetrics,
    aggregateMetrics,
    aggregateMetricsError,
    events,
    approvals,
    policyEvaluations,
    evaluationRun,
    evaluationRunError,
    configAuditFindings,
    configAuditError,
    openclawStatus,
    openclawStatusError,
    traceDetails,
    traceDetailErrors,
    traceDetailLoadingId,
    policySummary,
    policyError,
    auditIntegrity,
    auditIntegrityError,
    provenanceByTrace,
    provenanceErrors,
    health,
    status,
    error,
    lastUpdatedAt,
    isManualRefreshing,
    submittingApprovalId,
    approvalResolutionError,
    approvalResolutionState,
    pendingCount,
    decisionTrend,
    investigationIndex,
    attackDistribution,
    traces,
    ruleDistribution,
    activeScope,
    refresh,
    setActiveScope,
    loadAggregateMetrics,
    loadTraceDetail,
    loadTraceProvenance,
    resolveApproval,
    startPolling,
    stopPolling,
  };
});
