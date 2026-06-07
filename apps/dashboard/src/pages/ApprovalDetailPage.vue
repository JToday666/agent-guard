<template>
  <section class="approval-detail-page workspace-panel" aria-labelledby="approval-page-title">
    <header class="page-header">
      <div>
        <p>审批</p>
        <h1 id="approval-page-title">{{ approval?.id ?? approvalId }}</h1>
      </div>
      <RouterLink class="page-action" to="/approvals">返回审批队列</RouterLink>
    </header>

    <template v-if="approval">
      <section class="content-section">
        <h2>需要确认的 Agent 动作</h2>
        <p>{{ approval.reason }}</p>
        <dl>
          <div>
            <dt>工具</dt>
            <dd>{{ approval.tool }}</dd>
          </div>
          <div>
            <dt>目标</dt>
            <dd>{{ approval.resource }}</dd>
          </div>
          <div>
            <dt>状态</dt>
            <dd>{{ getApprovalStatusLabel(approval.status) }}</dd>
          </div>
        </dl>
        <div class="link-row">
          <RouterLink :to="`/events?event_id=${approval.eventId}`">查看事件</RouterLink>
          <RouterLink :to="`/traces/${approval.traceId}`">查看链路</RouterLink>
        </div>
      </section>
    </template>

    <EmptyState
      v-else
      message="当前审批记录不存在或已不在可查看范围内。"
      title="未找到审批记录"
    />
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";

import EmptyState from "../components/EmptyState.vue";
import { approvals } from "../mocks/dashboard-data";
import type { ApprovalStatus } from "../types/dashboard";

defineOptions({
  name: "ApprovalDetailPage",
});

const route = useRoute();
const approvalId = computed(() => String(route.params.approval_id));
const approval = computed(() => approvals.find((item) => item.id === approvalId.value));

function getApprovalStatusLabel(status: ApprovalStatus): string {
  if (status === "allowed") return "已允许一次";
  if (status === "denied") return "已拒绝";
  if (status === "expired") return "已过期";
  return "待处理";
}
</script>

<style scoped lang="scss">
.approval-detail-page {
  display: grid;
  gap: var(--space-5);
}

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
  font-weight: 700;
  margin: 0;
  overflow-wrap: anywhere;
  text-align: right;
}

p {
  margin: 0;
}

.link-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}
</style>
