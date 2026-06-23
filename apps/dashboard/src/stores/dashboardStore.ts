import { defineStore } from "pinia";
import { computed, ref } from "vue";

import { dashboardEnv } from "../config/dashboard-env";
import { dashboardDataSource } from "../data/dashboard-data-source-instance";
import { deriveMetrics, groupDecisionTrend } from "../data/dashboard-metrics";
import { buildInvestigationIndex } from "../data/investigation-index";
import {
  getRefreshFailureStatus,
  shouldEnterInitialLoading,
} from "../data/dashboard-refresh-state";
import {
  hasSameEventWindow,
  hasSameEvaluation,
  hasSameMetrics,
  reconcileApprovals,
} from "../data/dashboard-snapshot";
import type {
  ApprovalRequest,
  AuditEventRow,
  DataStatus,
  EvalMetrics,
  EvaluationSummary,
  HealthStatus,
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

const POLL_INTERVAL_MS = 10_000;

export const useDashboardStore = defineStore("dashboard", () => {
  const events = ref<AuditEventRow[]>([]);
  const approvals = ref<ApprovalRequest[]>([]);
  const metrics = ref<EvalMetrics>({ ...emptyMetrics });
  const evaluation = ref<EvaluationSummary>({
    asrBefore: null,
    asrAfter: null,
    blockRate: null,
    fpr: null,
    averageLatencyMs: null,
  });
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
  const decisionTrend = computed(() =>
    groupDecisionTrend(
      events.value.map((event) => ({
        ...event,
        latencyMs: event.latencyMs ?? null,
      })),
    ),
  );
  const investigationIndex = computed(() => buildInvestigationIndex(events.value));
  const attackDistribution = computed(() => {
    const counts = new Map<string, number>();
    for (const event of investigationIndex.value.latestEvents) {
      const key =
        event.attackType ||
        (event.caseId?.startsWith("BENIGN") ? "benign" : "unknown");
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((left, right) => right.value - left.value);
  });
  const traces = computed<TraceSummary[]>(() => {
    return [...investigationIndex.value.byTrace.entries()]
      .map(([id, rows]): TraceSummary => {
        const last = rows.at(-1)!;
        const isDenied = rows.some((event) => event.decision === "deny");
        const isPaused =
          !isDenied && rows.some((event) => event.decision === "ask");
        return {
          id,
          lastEventAt: last.occurredAt,
          caseId: last.caseId ?? "未提供",
          title: last.reason,
          status: isDenied ? "blocked" : isPaused ? "paused" : "allowed",
          approvalId: last.approvalId,
        };
      })
      .sort(
        (left, right) =>
          Date.parse(right.lastEventAt) - Date.parse(left.lastEventAt),
      );
  });

  async function performRefresh(): Promise<void> {
    const controller = new AbortController();
    activeController = controller;
    if (shouldEnterInitialLoading(status.value)) status.value = "loading";

    const results = await Promise.allSettled([
      dashboardDataSource.getEvents({}, controller.signal),
      dashboardDataSource.getMetrics({}, controller.signal),
      dashboardDataSource.getPendingApprovals(controller.signal),
      dashboardDataSource.getHealth(controller.signal),
    ] as const);

    const [eventsResult, metricsResult, approvalsResult, healthResult] =
      results;
    if (
      eventsResult.status === "fulfilled" &&
      !hasSameEventWindow(events.value, eventsResult.value)
    ) {
      events.value = eventsResult.value;
    }
    if (metricsResult.status === "fulfilled") {
      if (!hasSameMetrics(metrics.value, metricsResult.value)) {
        metrics.value = metricsResult.value;
      }
    } else if (eventsResult.status === "fulfilled") {
      const derivedMetrics = deriveMetrics(
        events.value.map((event) => ({
          ...event,
          latencyMs: event.latencyMs ?? null,
        })),
      );
      if (!hasSameMetrics(metrics.value, derivedMetrics)) {
        metrics.value = derivedMetrics;
      }
    }
    if (approvalsResult.status === "fulfilled") {
      approvals.value = reconcileApprovals(
        approvals.value,
        approvalsResult.value,
      );
    }
    if (healthResult.status === "fulfilled") health.value = healthResult.value;

    const failures = results.filter(
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
    try {
      const nextEvaluation = await dashboardDataSource.getEvaluation(
        metrics.value,
      );
      if (!hasSameEvaluation(evaluation.value, nextEvaluation)) {
        evaluation.value = nextEvaluation;
      }
    } finally {
      if (activeController === controller) activeController = null;
    }
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

  return {
    events,
    approvals,
    metrics,
    evaluation,
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
    dataSourceMode: dashboardEnv.dataSource,
    refresh,
    resolveApproval,
    startPolling,
    stopPolling,
  };
});
