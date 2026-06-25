<template>
  <section class="evaluation-page workspace-panel" aria-labelledby="evaluation-title">
    <header class="page-header"><div><p>AttackBench</p><h1 id="evaluation-title">安全评测</h1></div><DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" /></header>
    <ErrorState v-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="store.refresh" />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
    <template v-else>
      <AsrComparisonChart :before="store.evaluation.asrBefore" :after="store.evaluation.asrAfter" />
      <MetricStrip :items="metricItems" />
      <section class="evaluation-evidence section-divider" aria-labelledby="sample-title">
      <header><div><h2 id="sample-title">样本证据</h2><p>评测结论可追溯到对应的 Trace 与审计事件</p></div><span>{{ store.traces.length }} 个样本</span></header>
      <div v-if="store.traces.length" class="sample-list">
        <RouterLink v-for="trace in store.traces" :id="`case-${trace.caseId}`" :key="trace.id" :class="{ 'sample-list__selected': selectedCaseId === trace.caseId }" :to="`/investigations/${trace.id}`">
          <code>{{ trace.caseId }}</code><span>{{ trace.title }}</span><StatusBadge :label="getTraceStatusLabel(trace.status)" :tone="getTraceStatusTone(trace.status)" /><time>{{ formatDashboardDateTime(trace.lastEventAt) }}</time><strong>查看证据</strong>
        </RouterLink>
      </div>
      <EmptyState v-else title="暂无评测样本" message="AttackBench 结果写入审计后将在此展示。" />
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, watch } from "vue";
import { useRoute } from "vue-router";
import AsrComparisonChart from "../components/Charts/AsrComparisonChart.vue";
import DataFreshness from "../components/DataFreshness.vue";
import EmptyState from "../components/EmptyState.vue";
import MetricStrip from "../components/MetricStrip.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/States/ErrorState.vue";
import LoadingState from "../components/States/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { formatDashboardDateTime, getTraceStatusLabel, getTraceStatusTone } from "../utils/dashboard-formatters";

defineOptions({ name: "EvaluationPage" });
const store = useDashboardStore();
const route = useRoute();
const selectedCaseId = computed(() => typeof route.query.case_id === "string" ? route.query.case_id : "");
const metricItems = computed(() => [
  { detail: "deny 与 ask", label: "阻断率", route: "/investigations?blocked=true", tone: "success" as const, value: percent(store.evaluation.blockRate) },
  { detail: "正常样本被阻断", label: "误报率 FPR", route: "/investigations", value: percent(store.evaluation.fpr) },
  { detail: "安全判定", label: "平均判定延迟", route: "/system", value: store.evaluation.averageLatencyMs === null ? "--" : `${store.evaluation.averageLatencyMs.toFixed(1)} ms` },
  { detail: "当前数据窗口", label: "审计事件", route: "/investigations", value: String(store.metrics.eventCount) },
]);
function percent(value: number | null) { return value === null ? "--" : `${(value * 100).toFixed(1)}%`; }
watch([selectedCaseId, () => store.traces.length], async ([caseId]) => { if (!caseId) return; await nextTick(); document.getElementById(`case-${caseId}`)?.scrollIntoView({ block: "center", behavior: "smooth" }); }, { immediate: true });
</script>

<style scoped lang="scss">
.evaluation-page { display: grid; gap: var(--space-6); }
.evaluation-evidence { display: grid; gap: var(--space-4); }
.evaluation-evidence > header { align-items: start; display: flex; justify-content: space-between; }
.evaluation-evidence h2, .evaluation-evidence p { margin: 0; }
.evaluation-evidence p, .evaluation-evidence > header > span { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.sample-list { display: grid; }
.sample-list a { align-items: center; border-bottom: 1px solid var(--color-border); color: var(--color-text); display: grid; gap: var(--space-3); grid-template-columns: 8rem minmax(0, 1fr) 6rem 9rem 5rem; min-height: 3.75rem; padding: 0 var(--space-2); text-decoration: none; }
.sample-list a:hover { background: var(--color-row-hover); }
.sample-list__selected { background: var(--color-active-soft) !important; box-shadow: inset 2px 0 var(--color-active); }
.sample-list span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sample-list time { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.sample-list strong { color: var(--color-link); font-size: var(--font-size-12); }
@media (max-width: 760px) { .sample-list a { grid-template-columns: 1fr auto; padding: var(--space-3) 0; } .sample-list span { grid-column: 1 / -1; } .sample-list time { display: none; } }
</style>
