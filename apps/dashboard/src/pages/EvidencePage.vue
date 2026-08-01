<template>
  <section class="evidence-page workspace-panel" aria-labelledby="evidence-title">
    <header class="page-header">
      <div><h1 id="evidence-title">证据链</h1></div>
      <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
    </header>

    <ErrorState
      v-if="store.status === 'error' && store.error"
      :is-retrying="store.isRefreshing"
      :message="store.error"
      @retry="store.refresh"
    />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
    <template v-else-if="store.traces.length">
      <div class="evidence-summary">
        <strong>{{ store.traces.length }}</strong
        ><span>条证据链</span><span>按最新事件排序</span>
      </div>
      <div class="evidence-list">
        <RouterLink v-for="trace in store.traces" :key="trace.id" :to="`/evidence/${trace.id}`">
          <code>{{ trace.caseId }}</code>
          <span>{{ trace.title }}</span>
          <StatusBadge :label="getTraceStatusLabel(trace.status)" :tone="getTraceStatusTone(trace.status)" />
          <time>{{ formatDashboardDateTime(trace.lastEventAt) }}</time>
          <strong>查看证据链</strong>
        </RouterLink>
      </div>
    </template>
    <EmptyState v-else title="暂无证据链" message="审计事件写入后将在这里汇总同一任务的完整证据。" />
  </section>
</template>

<script setup lang="ts">
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { formatDashboardDateTime, getTraceStatusLabel, getTraceStatusTone } from "../utils/dashboard-formatters";

defineOptions({ name: "EvidencePage" });
const store = useDashboardStore();
</script>

<style scoped lang="scss">
.evidence-page {
  display: grid;
  gap: var(--space-5);
}
.evidence-summary {
  align-items: baseline;
  display: flex;
  gap: var(--space-2);
}
.evidence-summary span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.evidence-summary span:last-child {
  margin-left: auto;
}
.evidence-list {
  display: grid;
  min-width: 0;
}
.evidence-list a {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  color: var(--color-text);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(6rem, 8rem) minmax(0, 1fr) minmax(5rem, 6rem) minmax(8rem, 9rem) minmax(5rem, auto);
  min-height: 3.75rem;
  padding: 0 var(--space-2);
  text-decoration: none;
}
.evidence-list a:hover {
  background: var(--color-row-hover);
}
.evidence-list span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.evidence-list time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.evidence-list strong {
  color: var(--color-link);
  font-size: var(--font-size-12);
  text-align: right;
}
@media (max-width: 760px) {
  .evidence-list a {
    align-items: start;
    grid-template-columns: 1fr auto;
    padding: var(--space-3) 0;
  }
  .evidence-list span {
    grid-column: 1 / -1;
    white-space: normal;
  }
  .evidence-list time {
    display: none;
  }
  .evidence-list strong {
    text-align: left;
  }
}
</style>
