<template>
  <section class="overview-page workspace-panel" aria-labelledby="overview-title">
    <header class="page-header overview-header">
      <div>
        <p>安全监控</p>
        <h1 id="overview-title">安全态势总览</h1>
      </div>
      <div class="overview-header__actions">
        <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
        <button type="button" :aria-busy="store.isRefreshing" :disabled="store.isRefreshing" @click="handleRefresh">刷新数据</button>
      </div>
    </header>

    <ErrorState v-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="handleRefresh" />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" :rows="6" />
    <template v-else>
      <div class="metric-grid">
        <MetricCard label="审计事件" :value="formatCount(store.metrics.eventCount)" route="/events" tone="neutral" footnote="当前数据窗口" />
        <MetricCard label="已阻断" :value="formatCount(store.metrics.blockedCount)" route="/events?blocked=true" tone="danger" :footnote="formatPercent(store.metrics.blockRate)" />
        <MetricCard label="待审批" :value="formatCount(store.pendingCount)" route="/approvals" tone="warning" footnote="需要人工处理" />
        <MetricCard label="放行" :value="formatCount(store.metrics.allowCount)" route="/events?decision=allow" tone="success" footnote="正常动作" />
        <MetricCard label="误报率 FPR" :value="formatPercent(store.metrics.fpr)" route="/evaluation" tone="neutral" footnote="基于已标注样本" />
        <MetricCard label="平均判定延迟" :value="formatLatency(store.metrics.averageLatencyMs)" route="/evaluation" tone="neutral" footnote="安全判定" />
      </div>

      <div class="overview-grid">
        <section class="content-section overview-panel overview-panel--wide">
          <header class="panel-header"><div><h2>决策趋势</h2><p>最近各类决策的时间变化</p></div><RouterLink to="/events">查看事件</RouterLink></header>
          <DecisionTrendChart :points="store.decisionTrend" />
        </section>
        <section class="content-section overview-panel">
          <header class="panel-header"><div><h2>攻击类型分布</h2><p>当前事件窗口的类型构成</p></div></header>
          <AttackDistributionChart :items="store.attackDistribution" />
        </section>
      </div>

      <section class="content-section risk-section">
        <header class="panel-header"><div><h2>最新高风险事件</h2><p>优先展示严重与高风险事件</p></div><RouterLink to="/events?severity=high">全部高风险</RouterLink></header>
        <div v-if="highRiskEvents.length" class="risk-list">
          <RouterLink v-for="event in highRiskEvents" :key="event.id" :to="`/events?event_id=${event.id}`">
            <time>{{ event.time }}</time>
            <StatusBadge :label="getDecisionLabel(event.decision)" :tone="getDecisionTone(event.decision)" />
            <code>{{ event.tool }}</code>
            <span>{{ event.resource }}</span>
            <strong>{{ event.riskScore }}</strong>
          </RouterLink>
        </div>
        <EmptyState v-else title="暂无高风险事件" message="当前数据窗口内没有 critical 或 high 事件。" />
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
import MetricCard from "../components/MetricCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/States/ErrorState.vue";
import LoadingState from "../components/States/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { getDecisionLabel, getDecisionTone } from "../utils/dashboard-formatters";

defineOptions({ name: "OverviewPage" });
const store = useDashboardStore();
const highRiskEvents = computed(() => store.events
  .filter((event) => event.severity === "critical" || event.severity === "high")
  .slice(0, 6));
function formatCount(value: number) { return new Intl.NumberFormat("zh-CN").format(value); }
function formatPercent(value: number | null) { return value === null ? "--" : `${(value * 100).toFixed(1)}%`; }
function formatLatency(value: number | null) { return value === null ? "--" : `${value.toFixed(1)} ms`; }
function handleRefresh() { void store.refresh(); }
</script>

<style scoped lang="scss">
.overview-page { display: grid; gap: var(--space-5); }
.overview-header { margin-bottom: 0; }
.overview-header__actions { align-items: center; display: flex; flex-wrap: wrap; gap: var(--space-3); }
.overview-header__actions button {
  background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2);
  color: var(--color-text); cursor: pointer; min-height: 2.25rem; padding: 0 var(--space-3);
}
.metric-grid { display: grid; gap: var(--space-3); grid-template-columns: repeat(6, minmax(0, 1fr)); }
.overview-grid { display: grid; gap: var(--space-4); grid-template-columns: minmax(0, 1.55fr) minmax(18rem, 0.85fr); }
.overview-panel { min-height: 18rem; }
.panel-header { align-items: start; display: flex; gap: var(--space-4); justify-content: space-between; }
.panel-header p { color: var(--color-text-subtle); font-size: var(--font-size-12); margin: var(--space-1) 0 0; }
.panel-header a { min-height: 2rem; }
.risk-list { display: grid; }
.risk-list a {
  align-items: center; background: transparent; border: 0; border-bottom: 1px solid var(--color-border);
  border-radius: 0; display: grid; font-weight: var(--font-weight-medium); gap: var(--space-3);
  grid-template-columns: 5rem 5rem 8rem minmax(0, 1fr) 3rem; min-height: 3.5rem; padding: 0 var(--space-2);
}
.risk-list a:last-child { border-bottom: 0; }
.risk-list time { color: var(--color-text-subtle); }
.risk-list span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.risk-list strong { color: var(--color-danger); text-align: right; }
@media (max-width: 1180px) { .metric-grid { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 840px) { .overview-grid { grid-template-columns: 1fr; } }
@media (max-width: 640px) {
  .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .risk-list a { align-items: start; grid-template-columns: auto 1fr auto; padding: var(--space-3) 0; }
  .risk-list code, .risk-list span { grid-column: 1 / -1; }
}
</style>
