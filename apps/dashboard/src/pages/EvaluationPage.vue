<template>
  <section class="evaluation-page workspace-panel" aria-labelledby="evaluation-title">
    <header class="page-header"><div><h1 id="evaluation-title">安全评测</h1></div><DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" /></header>
    <ErrorState v-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="store.refresh" />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
    <template v-else>
      <AsrComparisonChart v-if="hasAsrData" :before="store.evaluation.asrBefore" :after="store.evaluation.asrAfter" />
      <section v-else class="evaluation-empty-asr" aria-labelledby="asr-empty-title"><h2 id="asr-empty-title">暂无评测结果</h2><p>请运行 AttackBench 评测并将结果写入审计后，数据将自动展示。</p></section>
      <MetricStrip :items="metricItems" />
      <section v-if="hasRuntimeComparison" class="eval-runtime section-divider" aria-labelledby="runtime-perf-title">
        <header><div><h2 id="runtime-perf-title">运行时延迟对比</h2><p>比较多个运行时的平均判定耗时</p></div></header>
        <div class="runtime-bars">
          <div v-for="row in runtimeLatency" :key="row.runtime" class="runtime-bar-row">
            <span class="runtime-bar-label">{{ row.runtime }}</span>
            <span class="runtime-bar-track"><i :style="{ width: `${row.pct}%` }"></i></span>
            <span class="runtime-bar-val">{{ row.avg === null ? '—' : `${row.avg.toFixed(1)} ms` }}</span>
          </div>
        </div>
      </section>
      <section class="eval-matrix section-divider" aria-labelledby="matrix-title">
        <header><div><h2 id="matrix-title">混淆矩阵</h2><p>查看恶意样本和正常样本的放行、阻断结果</p></div></header>
        <ConfusionMatrix v-if="hasMatrixData" :tp="matrix.tp" :fp="matrix.fp" :tn="matrix.tn" :fn="matrix.fn" />
        <p v-else class="eval-matrix__empty">暂无足够标注数据（需要 is_malicious 字段）</p>
      </section>
      <section class="evaluation-evidence section-divider" aria-labelledby="sample-title">
      <header><div><h2 id="sample-title">样本证据</h2><p>评测结论可追溯到对应的证据链与审计事件</p></div><span>{{ store.traces.length }} 个样本</span></header>
      <div v-if="store.traces.length" class="sample-list">
        <RouterLink v-for="trace in store.traces" :id="`case-${trace.caseId}`" :key="trace.id" :class="{ 'sample-list__selected': selectedCaseId === trace.caseId }" :to="`/evidence/${trace.id}`">
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
import ConfusionMatrix from "../components/ConfusionMatrix.vue";
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
const hasAsrData = computed(() => store.evaluation.asrBefore !== null && store.evaluation.asrAfter !== null);
const matrix = computed(() => {
  const events = store.events;
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const e of events) {
    if (e.isMalicious === null || e.isMalicious === undefined) continue;
    if (e.isMalicious && e.blocked) tp++;
    else if (!e.isMalicious && e.blocked) fp++;
    else if (!e.isMalicious && !e.blocked) tn++;
    else if (e.isMalicious && !e.blocked) fn++;
  }
  return { tp, fp, tn, fn };
});
const hasMatrixData = computed(() => matrix.value.tp + matrix.value.fp + matrix.value.tn + matrix.value.fn > 0);
const metricItems = computed(() => [
  { detail: "deny 与 ask", label: "阻断率", route: "/investigations?blocked=true", tone: "success" as const, value: percent(store.evaluation.blockRate) },
  { detail: "正常样本被阻断", label: "误报率 FPR", route: "/investigations", value: percent(store.evaluation.fpr) },
  { detail: "恶意样本被放行", label: "漏报率 FNR", route: "/investigations?decision=allow", value: percent(store.evaluation.fnr) },
  { detail: "安全判定", label: "平均判定延迟", route: "/system", value: store.evaluation.averageLatencyMs === null ? "--" : `${store.evaluation.averageLatencyMs.toFixed(1)} ms` },
  { detail: "当前数据窗口", label: "审计事件", route: "/investigations", value: String(store.metrics.eventCount) },
]);
function percent(value: number | null) { return value === null ? "--" : `${(value * 100).toFixed(1)}%`; }
const runtimeLatency = computed(() => {
  const runtimes = ["langgraph", "openclaw"] as const;
  const rows = runtimes.map((rt) => {
    const vals = store.events.filter((e) => e.runtime === rt && e.latencyMs != null).map((e) => e.latencyMs as number);
    const avg = vals.length ? vals.reduce((s, v) => s + v, 0) / vals.length : null;
    return { runtime: rt, avg };
  });
  const max = Math.max(1, ...rows.map((r) => r.avg ?? 0));
  return rows.map((r) => ({ ...r, pct: r.avg ? (r.avg / max) * 100 : 0 }));
});
const hasRuntimeComparison = computed(() => runtimeLatency.value.filter((row) => row.avg !== null).length > 1);
watch([selectedCaseId, () => store.traces.length], async ([caseId]) => { if (!caseId) return; await nextTick(); document.getElementById(`case-${caseId}`)?.scrollIntoView({ block: "center", behavior: "smooth" }); }, { immediate: true });
</script>

<style scoped lang="scss">
.evaluation-page { display: grid; gap: var(--space-6); }
.evaluation-empty-asr { border-block: 1px solid var(--color-border); display: grid; gap: var(--space-1); padding: var(--space-5) 0; }
.evaluation-empty-asr h2, .evaluation-empty-asr p { margin: 0; }
.evaluation-empty-asr h2 { font-size: var(--font-size-16); }
.evaluation-empty-asr p { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.eval-runtime { display: grid; gap: var(--space-4); }
.eval-runtime > header { align-items: start; display: flex; justify-content: space-between; }
.eval-runtime h2, .eval-runtime p { margin: 0; }
.eval-runtime > header > div > p { color: var(--color-text-subtle); font-size: var(--font-size-12); margin-top: var(--space-1); }
.runtime-bars { display: grid; gap: var(--space-3); }
.runtime-bar-row { align-items: center; display: grid; gap: var(--space-3); grid-template-columns: 6rem 1fr 5rem; }
.runtime-bar-label { font-size: var(--font-size-13); font-weight: var(--font-weight-semibold); }
.runtime-bar-track { background: var(--color-surface-muted); border-radius: 3px; height: .5rem; overflow: hidden; }
.runtime-bar-track i { background: linear-gradient(90deg, var(--color-active), #7aa7ff); border-radius: inherit; display: block; height: 100%; min-width: 3px; }
.runtime-bar-val { color: var(--color-text-muted); font-size: var(--font-size-13); font-variant-numeric: tabular-nums; text-align: right; }
.eval-matrix > header { align-items: start; display: flex; justify-content: space-between; }
.eval-matrix h2, .eval-matrix p { margin: 0; }
.eval-matrix > header > div > p { color: var(--color-text-subtle); font-size: var(--font-size-12); margin-top: var(--space-1); }
.eval-matrix__empty { color: var(--color-text-subtle); font-size: var(--font-size-13); margin: 0; }
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
