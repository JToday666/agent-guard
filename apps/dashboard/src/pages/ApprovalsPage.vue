<template>
  <section class="approvals-page workspace-panel" aria-labelledby="approvals-title">
    <header class="page-header">
      <div><h1 id="approvals-title">人工审批</h1></div>
      <div class="approval-header-status">
        <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
        <StatusBadge
          :label="`${store.pendingCount} 待处理`"
          :tone="store.pendingCount ? 'warning' : 'success'"
        />
      </div>
    </header>

    <div class="approvals-page__content">
      <InlineNotice
        v-if="isReadOnly"
        class="approval-readonly-notice"
        title="只读审批视图"
        tone="warning"
      >
        <p>{{ readonlyReason }}</p>
      </InlineNotice>
      <InlineNotice
        v-if="pageMessage"
        class="approval-page-message"
        title="审批队列已更新"
        tone="warning"
      >
        <p>{{ pageMessage }}</p>
      </InlineNotice>
      <div class="approvals-page__main">
        <ErrorState
          v-if="store.status === 'error' && store.error"
          :is-retrying="store.isManualRefreshing"
          :message="store.error"
          @retry="store.refresh"
        />
        <LoadingState v-else-if="store.status === 'loading' && !store.approvals.length" />
        <div
          v-else-if="sortedApprovals.length"
          class="approvals-layout"
          :class="{ 'approvals-layout--detail-route': requestedId }"
        >
          <aside ref="approvalQueueRef" class="approval-queue" aria-label="待审批队列">
            <header>
              <div><strong>风险队列</strong><small>优先处理风险高或即将过期的请求</small></div>
            </header>
            <button
              v-for="approval in sortedApprovals"
              :key="approval.id"
              type="button"
              :class="{ 'approval-queue__item--active': selectedApproval?.id === approval.id }"
              @click="handleSelectApproval(approval)"
            >
              <span class="approval-queue__top">
                <StatusBadge
                  :label="getRiskSeverityLabel(approval.severity)"
                  :tone="getRiskSeverityTone(approval.severity)"
                />
                <time :datetime="approval.expiresAt ?? undefined">{{
                  formatRelativeExpiry(approval.expiresAt)
                }}</time>
              </span>
              <strong>{{ approval.actionName }}</strong>
              <small>{{ approval.resource }}</small>
              <span
                class="approval-queue__score"
                :class="`approval-queue__score--${approval.severity}`"
              >
                风险 {{ approval.riskScore }}
              </span>
            </button>
          </aside>

          <div v-if="selectedApproval" class="approval-detail-pane">
            <RouterLink class="approval-detail-back" :to="approvalQueueRoute">
              返回审批队列
            </RouterLink>
            <ApprovalDetail
              :approval="selectedApproval"
              :approval-routes="selectedApprovalRoutes"
              :can-resolve-decision="canResolveDecision"
              :submitting-decision="isSubmitting ? pendingDecision : null"
              :action-message="actionMessage"
              :resolution-disabled-reason="resolutionDisabledReason"
              @resolve="handleResolveApproval"
            />
          </div>
          <div v-else class="approval-detail-pane">
            <EmptyState
              title="该审批不可用"
              message="该审批不在当前待处理快照中，可能已处理、过期或链接无效。系统不会自动改选其他请求。"
            >
              <RouterLink :to="approvalQueueRoute">返回审批队列</RouterLink>
            </EmptyState>
          </div>
        </div>
        <EmptyState
          v-else
          :title="requestedId ? '该审批不可用' : '审批队列已清空'"
          :message="
            requestedId
              ? '该审批不在当前待处理快照中，可能已处理、过期或链接无效。'
              : '当前没有等待人工处理的动作。'
          "
        >
          <RouterLink to="/investigations">查看调查事件</RouterLink>
        </EmptyState>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, onActivated, onDeactivated, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import ApprovalDetail from "../components/approvals/ApprovalDetail.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import InlineNotice from "../components/common/InlineNotice.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { dashboardDataSourceHandle } from "../data/sources";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";
import type { ApprovalRequest } from "../types/dashboard";
import { getApprovalEvidenceRoutes } from "../utils/approval-evidence-route";
import { formatRelativeApprovalExpiry, isApprovalExpired } from "../utils/approval-expiry";
import { getRiskSeverityLabel, getRiskSeverityTone } from "../utils/dashboard-formatters";

defineOptions({ name: "ApprovalsPage" });
const store = useDashboardStore();
const authStore = useAuthStore();
const route = useRoute();
const router = useRouter();
const isMockPreview = dashboardDataSourceHandle.descriptor.dataSourceMode === "mock_preview";
const actionMessage = ref("");
const pageMessage = ref("");
const pendingDecision = ref<"allow_once" | "deny" | null>(null);
const approvalQueueRef = ref<HTMLElement | null>(null);
const nowMs = ref(Date.now());
let expiryClock: number | undefined;
const isReadonlyRoute = computed(() => route.query.readonly === "1");
const hasApprovalMutationCapability =
  dashboardDataSourceHandle.descriptor.capabilities.approvalMutation &&
  dashboardDataSourceHandle.descriptor.capabilities.runtimeSupervisionS1;
const isReadOnly = computed(
  () => isMockPreview || !hasApprovalMutationCapability || isReadonlyRoute.value,
);
const readonlyReason = computed(() => {
  if (isMockPreview) {
    return "Mock Preview 使用固定合成样例，数据源不具备审批写入能力。移除 URL 参数也不会开放处理权限。";
  }
  if (!hasApprovalMutationCapability) {
    return "Runtime Supervision S1 尚未启用，审批依据仅供查看，不能提交处理结果。";
  }
  return "当前链接以只读方式打开，仅可查看审批依据，不能提交处理结果。";
});
const approvalQueueRoute = computed(() => ({
  path: "/approvals",
  query: isReadOnly.value ? { readonly: "1" } : {},
}));

function approvalDetailRoute(approvalId: string) {
  return {
    path: `/approvals/${approvalId}`,
    query: isReadOnly.value ? { readonly: "1" } : {},
  };
}

const sortedApprovals = computed(() =>
  [...store.approvals].sort((left, right) => {
    if (left.riskScore !== right.riskScore) return right.riskScore - left.riskScore;
    return (
      Date.parse(left.expiresAt ?? left.createdAt) - Date.parse(right.expiresAt ?? right.createdAt)
    );
  }),
);
const requestedId = computed(() =>
  typeof route.params.approval_id === "string" ? route.params.approval_id : "",
);
const selectedApproval = computed(() =>
  requestedId.value
    ? sortedApprovals.value.find((approval) => approval.id === requestedId.value)
    : sortedApprovals.value[0],
);
const selectedApprovalRoutes = computed(() =>
  selectedApproval.value ? getApprovalEvidenceRoutes(selectedApproval.value) : null,
);
const isSubmitting = computed(() => store.submittingApprovalId === selectedApproval.value?.id);
const isExpired = computed(() => {
  return isApprovalExpired(selectedApproval.value?.expiresAt, nowMs.value);
});
const resolutionDisabledReason = computed(() => {
  if (isReadOnly.value) return readonlyReason.value;
  if (isSubmitting.value) return "审批正在提交";
  if (!authStore.csrfToken) return "浏览器会话尚未就绪，请刷新页面后重试";
  if (isExpired.value) return "审批已过期，不能继续处理";
  if (!selectedApproval.value?.decisionOptions.length) return "服务端未提供可用的审批处理选项";
  if (
    !selectedApproval.value.decisionOptions.some((decision) =>
      store.canResolveApproval(selectedApproval.value!.id, decision),
    )
  ) {
    return "审批依据尚未完成 Live 精确关联，当前只能查看";
  }
  return "";
});

function canResolveDecision(decision: "allow_once" | "deny"): boolean {
  return Boolean(
    selectedApproval.value &&
    !resolutionDisabledReason.value &&
    store.canResolveApproval(selectedApproval.value.id, decision),
  );
}
const approvalIds = computed(() =>
  sortedApprovals.value.map((approval) => approval.id).join("\u0000"),
);
watch(
  [requestedId, approvalIds, () => store.status],
  () => {
    if (route.name !== "approvals") return;
    if (store.status === "idle" || store.status === "loading") return;
    if (!sortedApprovals.value.length) return;
    if (
      requestedId.value &&
      !store.approvals.some((approval) => approval.id === requestedId.value)
    ) {
      pageMessage.value = "该审批已不在待处理队列中；为避免误操作，未自动选择其他请求。";
    }
  },
  { immediate: true },
);

function startExpiryClock() {
  window.clearInterval(expiryClock);
  nowMs.value = Date.now();
  expiryClock = window.setInterval(() => {
    nowMs.value = Date.now();
  }, 1_000);
}
function stopExpiryClock() {
  window.clearInterval(expiryClock);
}
onActivated(startExpiryClock);
onActivated(() => store.setApprovalMutationReadOnlyOverride(isReadOnly.value));
onDeactivated(() => {
  stopExpiryClock();
  store.setApprovalMutationReadOnlyOverride(true);
});
onUnmounted(() => {
  stopExpiryClock();
  store.setApprovalMutationReadOnlyOverride(true);
});
watch(
  isReadOnly,
  (value) => {
    store.setApprovalMutationReadOnlyOverride(value);
    if (!value && selectedApproval.value) {
      void store.prepareApprovalMutation(selectedApproval.value.id);
    }
  },
  { immediate: true },
);
watch(
  () => selectedApproval.value?.id,
  (approvalId) => {
    if (!isSubmitting.value) actionMessage.value = "";
    if (approvalId) void store.prepareApprovalMutation(approvalId);
  },
  { immediate: true },
);
watch(requestedId, async (approvalId, previousApprovalId) => {
  if (approvalId === previousApprovalId || !window.matchMedia("(max-width: 56.25rem)").matches) {
    return;
  }
  await nextTick();
  if (approvalId) {
    document.querySelector<HTMLElement>(".approval-detail-back")?.focus();
    return;
  }
  approvalQueueRef.value
    ?.querySelector<HTMLElement>(".approval-queue__item--active, button")
    ?.focus();
});

function handleSelectApproval(approval: ApprovalRequest) {
  actionMessage.value = "";
  pageMessage.value = "";
  void router.push(approvalDetailRoute(approval.id));
}
async function handleResolveApproval(decision: "allow_once" | "deny") {
  if (!selectedApproval.value || !canResolveDecision(decision)) return;
  const id = selectedApproval.value.id;
  const traceRoute = selectedApprovalRoutes.value?.trace;
  actionMessage.value = "";
  pageMessage.value = "";
  pendingDecision.value = decision;
  try {
    await store.resolveApproval(id, decision);
    actionMessage.value =
      decision === "deny"
        ? "已记录拒绝授权；实际状态以运行时回执为准"
        : "已记录仅本次放行；是否执行以运行时回执为准";
    if (traceRoute) {
      void router.push(traceRoute);
      return;
    }
  } catch {
    const message = store.approvalResolutionError ?? "审批提交失败";
    if (
      store.approvalResolutionState === "conflict" ||
      store.approvalResolutionState === "uncertain"
    ) {
      pageMessage.value = message;
    } else {
      actionMessage.value = message;
    }
  } finally {
    pendingDecision.value = null;
  }
}
function formatRelativeExpiry(value?: string | null) {
  return formatRelativeApprovalExpiry(value, nowMs.value);
}
</script>

<style scoped lang="scss">
.approvals-page {
  display: grid;
  gap: var(--space-5);
  grid-template-rows: auto minmax(0, 1fr);
  height: calc(100dvh - var(--top-bar-height));
  overflow: hidden;
}
.approval-header-status {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.approvals-page__content {
  display: grid;
  gap: var(--space-3);
  grid-template-rows: auto auto minmax(0, 1fr);
  min-height: 0;
}
.approvals-page__main {
  grid-row: 3;
  height: 100%;
  min-height: 0;
}
.approvals-layout {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(15rem, 20rem) minmax(0, 1fr);
  height: 100%;
  min-height: 0;
  min-width: 0;
  overflow: hidden;
}
.approval-detail-pane {
  display: grid;
  grid-template-rows: minmax(0, 1fr);
  min-height: 0;
  min-width: 0;
}
.approval-detail-back {
  display: none;
}
.approval-queue {
  align-content: start;
  border-right: 1px solid var(--color-border);
  display: grid;
  gap: 0;
  grid-auto-rows: max-content;
  height: 100%;
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  padding-right: var(--space-4);
}
.approval-queue > header {
  padding: var(--space-2);
}
.approval-queue > header small {
  color: var(--color-text-subtle);
  display: block;
  margin-top: var(--space-1);
}
.approval-queue > button {
  background: transparent;
  border: 0;
  border-bottom: 1px solid var(--color-border);
  color: var(--color-text);
  cursor: pointer;
  display: grid;
  gap: var(--space-2);
  min-width: 0;
  padding: var(--space-4) var(--space-3);
  position: relative;
  text-align: left;
}
.approval-queue > button::before {
  background: var(--gradient-active-track);
  content: "";
  inset: var(--space-3) auto var(--space-3) 0;
  position: absolute;
  transform: scaleY(0);
  transform-origin: center;
  transition: transform var(--transition-fast);
  width: 3px;
}
.approval-queue > button:hover {
  background: var(--color-row-hover);
}
.approval-queue > button.approval-queue__item--active {
  background: var(--gradient-active-row);
}
.approval-queue > button.approval-queue__item--active::before {
  transform: scaleY(1);
}
.approval-queue__top {
  align-items: center;
  display: flex;
  gap: var(--space-2);
  justify-content: space-between;
  min-width: 0;
}
.approval-queue__top time,
.approval-queue > button small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.approval-queue__score {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-bold);
}
.approval-queue__score--critical,
.approval-queue__score--high {
  color: var(--color-danger);
}
.approval-queue__score--medium {
  color: var(--color-warning);
}

@media (max-width: 56.25rem) {
  .approvals-layout {
    grid-template-columns: 1fr;
  }

  .approval-queue {
    border-right: 0;
    padding-right: 0;
  }

  .approval-detail-pane {
    display: none;
    grid-template-rows: auto minmax(0, 1fr);
  }

  .approvals-layout--detail-route .approval-queue {
    display: none;
  }

  .approvals-layout--detail-route .approval-detail-pane {
    display: grid;
  }

  .approval-detail-back {
    align-items: center;
    color: var(--color-link);
    display: inline-flex;
    font-size: var(--font-size-13);
    font-weight: var(--font-weight-semibold);
    justify-self: start;
    min-height: 2.25rem;
    text-decoration: none;
  }
}
</style>
