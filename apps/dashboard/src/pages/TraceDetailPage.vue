<template>
  <section class="trace-detail-page workspace-panel" aria-labelledby="trace-detail-title">
    <header class="page-header">
      <div>
        <p>链路</p>
        <h1 id="trace-detail-title">{{ trace?.id ?? traceId }}</h1>
      </div>
      <RouterLink class="page-action" to="/traces">返回 Trace 列表</RouterLink>
    </header>

    <template v-if="trace">
      <section class="content-section">
        <h2>{{ trace.title }}</h2>
        <ol class="timeline">
          <li v-for="node in trace.nodes" :key="node">{{ node }}</li>
        </ol>
        <div class="link-row">
          <RouterLink :to="`/events?event_id=${trace.eventId}`">审计事件</RouterLink>
          <RouterLink v-if="trace.approvalId" :to="`/approvals/${trace.approvalId}`">
            审批
          </RouterLink>
          <RouterLink :to="`/evaluation?case_id=${trace.caseId}`">样本</RouterLink>
        </div>
      </section>
    </template>

    <EmptyState v-else message="当前链路不存在或数据未生成。" title="未找到链路" />
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";

import EmptyState from "../components/EmptyState.vue";
import { traces } from "../mocks/dashboard-data";

defineOptions({
  name: "TraceDetailPage",
});

const route = useRoute();
const traceId = computed(() => String(route.params.trace_id));
const trace = computed(() => traces.find((item) => item.id === traceId.value));
</script>

<style scoped lang="scss">
.trace-detail-page {
  display: grid;
  gap: var(--space-5);
}

.timeline {
  display: grid;
  gap: var(--space-3);
  list-style: none;
  margin: 0;
  padding: 0;

  li {
    background: var(--color-surface-muted);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    padding: var(--space-3);

    &:hover {
      background: var(--color-row-hover);
      border-color: var(--color-active-border);
    }
  }
}
</style>
