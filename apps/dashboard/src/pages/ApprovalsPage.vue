<template>
  <section class="approvals-page workspace-panel" aria-labelledby="approvals-title">
    <header class="page-header">
      <div>
        <p>监控</p>
        <h1 id="approvals-title">审批</h1>
      </div>
      <StatusBadge :label="`${pendingApprovals.length} 待处理`" tone="warning" />
    </header>

    <div class="approvals-page__layout">
      <section class="content-section" aria-labelledby="approval-queue-title">
        <h2 id="approval-queue-title">审批队列</h2>
        <div class="approval-list">
          <button
            v-for="approval in sortedApprovals"
            :key="approval.id"
            type="button"
            :class="{ 'approval-list__item--selected': selectedApproval?.id === approval.id }"
            @click="handleSelectApproval(approval)"
          >
            <strong>{{ approval.id }}</strong>
            <span>{{ approval.tool }}</span>
            <small>{{ approval.resource }}</small>
          </button>
        </div>
      </section>

      <section
        v-if="selectedApproval"
        class="content-section approval-detail"
        aria-labelledby="approval-detail-title"
      >
        <h2 id="approval-detail-title">审批详情</h2>
        <StatusBadge :label="getApprovalStatusLabel(resolutionStatus)" :tone="resolutionTone" />
        <dl>
          <div>
            <dt>工具</dt>
            <dd>{{ selectedApproval.tool }}</dd>
          </div>
          <div>
            <dt>目标</dt>
            <dd>{{ selectedApproval.resource }}</dd>
          </div>
          <div>
            <dt>风险分数</dt>
            <dd>{{ selectedApproval.riskScore }}</dd>
          </div>
          <div>
            <dt>严重性</dt>
            <dd>{{ getSeverityLabel(selectedApproval.severity) }}</dd>
          </div>
        </dl>
        <p>{{ selectedApproval.reason }}</p>
        <p><strong>放行后果:</strong> {{ selectedApproval.consequence }}</p>
        <div class="approval-detail__actions">
          <button type="button" @click="handleResolve('denied')">拒绝</button>
          <button type="button" @click="handleResolve('allowed')">允许一次</button>
          <RouterLink :to="`/traces/${selectedApproval.traceId}`">查看链路</RouterLink>
          <RouterLink :to="`/events?event_id=${selectedApproval.eventId}`">查看事件</RouterLink>
        </div>
      </section>
      <EmptyState
        v-else-if="sortedApprovals.length === 0"
        class="approvals-page__empty"
        message="当前没有待处理或已处理的审批请求。"
        title="暂无审批"
        variant="empty"
      >
        <RouterLink to="/events">查看事件</RouterLink>
      </EmptyState>
      <EmptyState
        v-else
        class="approvals-page__empty"
        :message="`审批 ${requestedApprovalId} 不存在或已不在可查看范围内。`"
        title="未找到审批记录"
        variant="not-found"
      >
        <RouterLink to="/approvals">返回审批队列</RouterLink>
      </EmptyState>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, reactive } from "vue";
import { useRoute, useRouter } from "vue-router";

import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { approvals } from "../mocks/dashboard-data";
import type { ApprovalRequest, ApprovalStatus } from "../types/dashboard";

defineOptions({
  name: "ApprovalsPage",
});

const route = useRoute();
const router = useRouter();

const sortedApprovals = computed(() =>
  [...approvals].sort((left, right) => {
    if (left.status === "pending" && right.status !== "pending") return -1;
    if (left.status !== "pending" && right.status === "pending") return 1;
    return Date.parse(right.createdAt) - Date.parse(left.createdAt);
  }),
);

const requestedApprovalId = computed(() =>
  typeof route.params.approval_id === "string" ? route.params.approval_id : "",
);

const selectedApproval = computed<ApprovalRequest | undefined>(() => {
  if (requestedApprovalId.value) {
    return sortedApprovals.value.find((approval) => approval.id === requestedApprovalId.value);
  }
  return sortedApprovals.value[0];
});

const pendingApprovals = computed(() => approvals.filter((approval) => approval.status === "pending"));
const resolvedByApprovalId = reactive(new Map<string, ApprovalStatus>());
const resolutionStatus = computed(() => {
  if (!selectedApproval.value) return "expired";
  return resolvedByApprovalId.get(selectedApproval.value.id) ?? selectedApproval.value.status;
});
const resolutionTone = computed(() => {
  if (resolutionStatus.value === "allowed") return "success";
  if (resolutionStatus.value === "denied" || resolutionStatus.value === "expired") return "danger";
  return "warning";
});

function handleResolve(status: "allowed" | "denied"): void {
  if (!selectedApproval.value) return;
  resolvedByApprovalId.set(selectedApproval.value.id, status);
}

function handleSelectApproval(approval: ApprovalRequest): void {
  void router.push(`/approvals/${approval.id}`);
}

function getApprovalStatusLabel(status: ApprovalStatus): string {
  if (status === "allowed") return "已允许一次";
  if (status === "denied") return "已拒绝";
  if (status === "expired") return "已过期";
  return "待处理";
}

function getSeverityLabel(severity: ApprovalRequest["severity"]): string {
  if (severity === "critical") return "严重";
  if (severity === "high") return "高";
  if (severity === "medium") return "中";
  return "低";
}
</script>

<style scoped lang="scss">
.approvals-page {
  display: grid;
  gap: var(--space-5);
}

.approvals-page__layout {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(16rem, 22rem) minmax(0, 1fr);
}

.approval-list {
  display: grid;
  gap: var(--space-2);
}

.approval-list button {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  cursor: pointer;
  display: grid;
  gap: var(--space-1);
  min-height: 5rem;
  min-width: 0;
  padding: var(--space-3);
  text-align: left;

  &:hover {
    background: var(--color-row-hover);
    border-color: var(--color-active-border);
  }

  strong {
    font-weight: var(--font-weight-bold);
  }

  span,
  small {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  small {
    color: var(--color-text-muted);
  }
}

.approval-list__item--selected {
  background: var(--color-active-soft) !important;
  border-color: var(--color-active-border) !important;
  box-shadow: inset 3px 0 0 var(--color-active);
}

.approval-detail {
  align-content: start;
  display: grid;
  gap: var(--space-4);

  dl {
    display: grid;
    gap: var(--space-2);
    margin: 0;
  }

  dl > div {
    display: flex;
    gap: var(--space-3);
    justify-content: space-between;
  }

  dt {
    color: var(--color-text-subtle);
  }

  dd {
    font-weight: var(--font-weight-semibold);
    margin: 0;
    overflow-wrap: anywhere;
    text-align: right;
  }

  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
}

.approval-detail__actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);

  button,
  a {
    align-items: center;
    background: var(--color-surface-muted);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    color: var(--color-text);
    cursor: pointer;
    display: inline-flex;
    font-weight: var(--font-weight-semibold);
    min-height: 2.5rem;
    padding: 0 var(--space-3);
    text-decoration: none;

    &:hover {
      background: var(--color-active-soft);
      border-color: var(--color-active-border);
      color: var(--color-active);
    }
  }
}

@media (max-width: 820px) {
  .approvals-page__layout {
    grid-template-columns: 1fr;
  }
}
</style>
