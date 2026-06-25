<template>
  <section class="overview-page workspace-panel" aria-labelledby="overview-title">
    <header class="page-header overview-header">
      <div><p>安全态势</p><h1 id="overview-title">运行风险总览</h1></div>
      <div class="overview-header__actions"><DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" /><button type="button" :aria-busy="store.isRefreshing" :disabled="store.isRefreshing" @click="handleRefresh">{{ store.isRefreshing ? "刷新中" : "刷新数据" }}</button></div>
    </header>

    <ErrorState v-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="handleRefresh" />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" :rows="6" />
    <template v-else>
      <MetricStrip :items="metricItems" />

      <div class="analysis-grid section-divider">
        <section class="analysis-panel analysis-panel--trend" aria-labelledby="trend-title">
          <header><div><h2 id="trend-title">决策趋势</h2><p>当前事件窗口内的放行、审批与拒绝变化</p></div><RouterLink class="page-action" to="/investigations">进入调查</RouterLink></header>
          <DecisionTrendChart :points="store.decisionTrend" />
        </section>
        <section class="analysis-panel" aria-labelledby="distribution-title">
          <header><div><h2 id="distribution-title">攻击类型</h2><p>按事件量排序，直接显示数量与相对规模</p></div></header>
          <AttackDistributionChart :items="store.attackDistribution" />
        </section>
      </div>

      <section class="risk-feed section-divider" aria-labelledby="risk-feed-title">
        <header><div><h2 id="risk-feed-title">需要关注的高风险事件</h2><p>严重与高风险事件按最新时间排列</p></div><RouterLink class="page-action" to="/investigations?severity=high">查看全部</RouterLink></header>
        <div v-if="highRiskEvents.length" class="risk-feed__rows">
          <RouterLink v-for="event in highRiskEvents" :key="event.id" :to="{ path: '/investigations', query: { event_id: event.id } }">
            <time>{{ event.time }}</time><StatusBadge :label="getDecisionLabel(event.decision)" :tone="getDecisionTone(event.decision)" /><code>{{ event.tool }}</code><span>{{ event.resource }}</span><span class="risk-rail"><i :style="{ width: `${event.riskScore}%` }"></i></span><strong>{{ event.riskScore }}</strong>
          </RouterLink>
        </div>
        <EmptyState v-else title="暂无高风险事件" message="当前数据窗口内没有严重或高风险事件。" />
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import AttackDistributionChart from "../components/Charts/AttackDistributionChart.vue";
import DecisionTrendChart from "../components/Charts/DecisionTrendChart.vue";
import DataFreshness from "../components/DataFreshness.vue";
import EmptyState from "../components/EmptyState.vue";
import MetricStrip from "../components/MetricStrip.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/States/ErrorState.vue";
import LoadingState from "../components/States/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { getDecisionLabel, getDecisionTone } from "../utils/dashboard-formatters";

defineOptions({ name: "OverviewPage" });
const store = useDashboardStore();
const countFormatter = new Intl.NumberFormat("zh-CN");
const highRiskEvents = computed(() => store.investigationIndex.latestEvents.filter((event) => event.severity === "critical" || event.severity === "high").slice(0, 6));
const metricItems = computed(() => [
  { detail: "当前数据窗口", label: "审计事件", route: "/investigations", value: countFormatter.format(store.metrics.eventCount) },
  { detail: formatPercent(store.metrics.blockRate), label: "已阻断", route: "/investigations?blocked=true", tone: "danger" as const, value: countFormatter.format(store.metrics.blockedCount) },
  { detail: "需要人工处理", label: "待审批", route: "/approvals", tone: "warning" as const, value: countFormatter.format(store.pendingCount) },
  { detail: "正常动作", label: "已放行", route: "/investigations?decision=allow", tone: "success" as const, value: countFormatter.format(store.metrics.allowCount) },
  { detail: "已标注样本", label: "误报率 FPR", route: "/evaluation", value: formatPercent(store.metrics.fpr) },
  { detail: "安全判定", label: "平均延迟", route: "/evaluation", value: store.metrics.averageLatencyMs === null ? "--" : `${store.metrics.averageLatencyMs.toFixed(1)} ms` },
]);
function formatPercent(value: number | null) { return value === null ? "--" : `${(value * 100).toFixed(1)}%`; }
function handleRefresh() { void store.refresh(); }
</script>

<style scoped lang="scss">
.overview-page { display: grid; gap: var(--space-6); }
.overview-header { margin-bottom: 0; }
.overview-header__actions { align-items: center; display: flex; flex-wrap: wrap; gap: var(--space-3); }
.overview-header__actions button { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); cursor: pointer; min-height: 2.25rem; padding: 0 var(--space-3); }
.analysis-grid { display: grid; gap: clamp(var(--space-6), 4vw, 3rem); grid-template-columns: minmax(0, 1.55fr) minmax(18rem, .75fr); }
.analysis-panel { display: grid; gap: var(--space-5); min-width: 0; }
.analysis-panel > header, .risk-feed > header { align-items: start; display: flex; gap: var(--space-4); justify-content: space-between; }
.analysis-panel h2, .analysis-panel p, .risk-feed h2, .risk-feed p { margin: 0; }
.analysis-panel p, .risk-feed p { color: var(--color-text-subtle); font-size: var(--font-size-12); margin-top: var(--space-1); }
.analysis-panel > header .page-action, .risk-feed > header .page-action { font-size: var(--font-size-13); }
.risk-feed { display: grid; gap: var(--space-4); }
.risk-feed__rows { display: grid; }
.risk-feed__rows > a { align-items: center; border-bottom: 1px solid var(--color-border); color: var(--color-text); display: grid; font-size: var(--font-size-13); gap: var(--space-3); grid-template-columns: 5rem 5rem 8rem minmax(10rem, 1fr) minmax(4rem, 8rem) 2.5rem; min-height: 3.5rem; padding: 0 var(--space-2); text-decoration: none; }
.risk-feed__rows > a:hover { background: var(--color-row-hover); }
.risk-feed time { color: var(--color-text-subtle); }
.risk-feed__rows span:not(.risk-rail) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.risk-rail { background: var(--color-surface-muted); height: .3rem; overflow: hidden; }
.risk-rail i { background: var(--color-danger); display: block; height: 100%; }
.risk-feed__rows strong { color: var(--color-danger); text-align: right; }
@media (max-width: 900px) { .analysis-grid { grid-template-columns: 1fr; } }
@media (max-width: 640px) { .risk-feed__rows > a { align-items: start; grid-template-columns: auto 1fr auto; padding: var(--space-3) 0; } .risk-feed__rows code, .risk-feed__rows span:not(.risk-rail) { grid-column: 1 / -1; } .risk-rail { grid-column: 1 / 3; width: 100%; } }
</style>
