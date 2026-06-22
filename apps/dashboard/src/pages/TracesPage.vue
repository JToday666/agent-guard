<template>
  <section class="traces-page workspace-panel" aria-labelledby="traces-title">
    <header class="page-header">
      <div><p>证据链</p><h1 id="traces-title">攻击链路</h1></div>
      <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
    </header>
    <div v-if="store.traces.length" class="trace-grid">
      <RouterLink v-for="trace in store.traces" :key="trace.id" class="trace-card" :to="`/traces/${trace.id}`">
        <header><StatusBadge :label="getTraceStatusLabel(trace.status)" :tone="getTraceStatusTone(trace.status)" /><time>{{ formatDashboardDateTime(trace.lastEventAt) }}</time></header>
        <strong>{{ trace.title }}</strong>
        <div class="trace-card__meta"><code>{{ trace.id }}</code><span>{{ trace.caseId }}</span></div>
        <ol><li v-for="node in trace.nodes.slice(0, 4)" :key="node">{{ node }}</li></ol>
      </RouterLink>
    </div>
    <EmptyState v-else title="暂无链路" message="当前没有可展示的链路事件。" />
  </section>
</template>
<script setup lang="ts">
import DataFreshness from "../components/DataFreshness.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import {
  formatDashboardDateTime,
  getTraceStatusLabel,
  getTraceStatusTone,
} from "../utils/dashboard-formatters";
defineOptions({ name: "TracesPage" });
const store = useDashboardStore();
</script>
<style scoped lang="scss">
.traces-page { display: grid; gap: var(--space-5); }
.trace-grid { display: grid; gap: var(--space-4); grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr)); }
.trace-card { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); color: var(--color-text); display: grid; gap: var(--space-4); padding: var(--space-4); text-decoration: none; }
.trace-card:hover { border-color: var(--color-active-border); box-shadow: var(--shadow-raised); transform: translateY(-1px); }
.trace-card header, .trace-card__meta { align-items: center; display: flex; gap: var(--space-3); justify-content: space-between; }
.trace-card time, .trace-card__meta span { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.trace-card > strong { font-size: var(--font-size-16); }
.trace-card ol { display: grid; gap: 0; list-style: none; margin: 0; padding: 0 0 0 var(--space-3); }
.trace-card li { border-left: 2px solid var(--color-border); color: var(--color-text-muted); font-size: var(--font-size-12); padding: var(--space-2) var(--space-3); }
.trace-card li:last-child { border-left-color: var(--color-active); }
</style>
