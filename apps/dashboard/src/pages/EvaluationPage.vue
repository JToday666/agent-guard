<template>
  <section class="evaluation-page workspace-panel" aria-labelledby="evaluation-title">
    <header class="page-header"><div><p>AttackBench</p><h1 id="evaluation-title">安全评测</h1></div><DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" /></header>
    <div class="comparison">
      <article><span>防护前 ASR</span><strong>{{ percent(store.evaluation.asrBefore) }}</strong><small>攻击成功率基线</small></article>
      <div class="comparison__arrow" aria-hidden="true">→</div>
      <article class="comparison__after"><span>防护后 ASR</span><strong>{{ percent(store.evaluation.asrAfter) }}</strong><small>启用 AgentGuard 后</small></article>
      <div class="comparison__delta"><span>ASR 降幅</span><strong>{{ reduction }}</strong></div>
    </div>
    <div class="evaluation-metrics">
      <MetricCard label="阻断率" :value="percent(store.evaluation.blockRate)" route="/events?blocked=true" tone="success" footnote="deny 与 ask" />
      <MetricCard label="误报率 FPR" :value="percent(store.evaluation.fpr)" route="/events" tone="neutral" footnote="正常样本被阻断" />
      <MetricCard label="平均判定延迟" :value="latency" route="/system" tone="neutral" footnote="安全判定" />
      <MetricCard label="审计事件" :value="String(store.metrics.eventCount)" route="/events" tone="neutral" footnote="当前数据窗口" />
    </div>
    <section class="content-section evaluation-evidence">
      <header><div><h2>样本证据</h2><p>每个结果均可下钻到真实事件和 Trace</p></div></header>
      <div v-if="store.traces.length" class="sample-table">
        <RouterLink v-for="trace in store.traces" :key="trace.id" :to="`/traces/${trace.id}`">
          <code>{{ trace.caseId }}</code><span>{{ trace.title }}</span><StatusBadge :label="getTraceStatusLabel(trace.status)" :tone="getTraceStatusTone(trace.status)" /><strong>查看证据</strong>
        </RouterLink>
      </div>
      <EmptyState v-else title="暂无评测样本" message="AttackBench 结果写入审计后将在此展示。" />
    </section>
  </section>
</template>
<script setup lang="ts">
import { computed } from "vue";
import DataFreshness from "../components/DataFreshness.vue";
import EmptyState from "../components/EmptyState.vue";
import MetricCard from "../components/MetricCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { getTraceStatusLabel, getTraceStatusTone } from "../utils/dashboard-formatters";
defineOptions({ name: "EvaluationPage" });
const store = useDashboardStore();
function percent(value: number | null) { return value === null ? "--" : `${(value * 100).toFixed(1)}%`; }
const reduction = computed(() => store.evaluation.asrBefore === null || store.evaluation.asrAfter === null ? "--" : `${((store.evaluation.asrBefore - store.evaluation.asrAfter) * 100).toFixed(1)}pp`);
const latency = computed(() => store.evaluation.averageLatencyMs === null ? "--" : `${store.evaluation.averageLatencyMs.toFixed(1)} ms`);
</script>
<style scoped lang="scss">
.evaluation-page { display: grid; gap: var(--space-5); }
.comparison { align-items: stretch; display: grid; gap: var(--space-3); grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) minmax(10rem, .65fr); }
.comparison article, .comparison__delta { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); display: grid; gap: var(--space-2); padding: var(--space-5); }
.comparison article > span, .comparison__delta span { color: var(--color-text-muted); font-size: var(--font-size-13); }
.comparison article strong { color: var(--color-danger); font-size: 2.25rem; }
.comparison article small { color: var(--color-text-subtle); }
.comparison article.comparison__after { border-color: var(--color-success-border); }
.comparison article.comparison__after strong, .comparison__delta strong { color: var(--color-success); }
.comparison__arrow { align-items: center; color: var(--color-text-subtle); display: flex; font-size: var(--font-size-24); }
.comparison__delta { align-content: center; background: var(--color-success-soft); border-color: var(--color-success-border); }
.comparison__delta strong { font-size: var(--font-size-24); }
.evaluation-metrics { display: grid; gap: var(--space-3); grid-template-columns: repeat(4, 1fr); }
.evaluation-evidence > header h2, .evaluation-evidence > header p { margin: 0; }
.evaluation-evidence > header p { color: var(--color-text-subtle); margin-top: var(--space-1); }
.sample-table { display: grid; }
.sample-table a { align-items: center; background: transparent; border: 0; border-bottom: 1px solid var(--color-border); border-radius: 0; color: var(--color-text); display: grid; gap: var(--space-3); grid-template-columns: 8rem minmax(0, 1fr) 5rem 5rem; min-height: 3.5rem; text-decoration: none; }
.sample-table a:last-child { border-bottom: 0; }
.sample-table span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sample-table strong { color: var(--color-link); font-size: var(--font-size-12); }
@media (max-width: 900px) { .comparison { grid-template-columns: 1fr 1fr; } .comparison__arrow { display: none; } .evaluation-metrics { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 600px) { .comparison { grid-template-columns: 1fr; } .sample-table a { grid-template-columns: 1fr auto; padding: var(--space-3) 0; } .sample-table span { grid-column: 1 / -1; } }
</style>
