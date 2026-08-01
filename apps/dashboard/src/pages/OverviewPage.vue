<template>
  <section class="overview-page workspace-panel" aria-labelledby="overview-title">
    <header class="page-header overview-header">
      <div><h1 id="overview-title">安全总览</h1></div>
      <div class="overview-header__actions">
        <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" /><button
          type="button"
          :aria-busy="store.isRefreshing"
          :disabled="store.isRefreshing"
          @click="handleRefresh"
        >
          {{ store.isRefreshing ? "刷新中" : "刷新数据" }}
        </button>
      </div>
    </header>

    <ErrorState
      v-if="store.status === 'error' && store.error"
      :is-retrying="store.isRefreshing"
      :message="store.error"
      @retry="handleRefresh"
    />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" :rows="6" />
    <template v-else>
      <MetricStrip :items="metricItems" />

      <div class="analysis-grid section-divider">
        <section class="analysis-panel analysis-panel--trend" aria-labelledby="trend-title">
          <header>
            <div>
              <h2 id="trend-title">决策趋势</h2>
              <p>查看最近审计事件中已放行、待审批与已阻断的变化</p>
            </div>
            <RouterLink class="page-action" to="/investigations">进入调查</RouterLink>
          </header>
          <DecisionTrendChart :points="store.decisionTrend" />
        </section>
        <section class="analysis-panel" aria-labelledby="distribution-title">
          <header>
            <div>
              <h2 id="distribution-title">攻击类型</h2>
              <p>按审计事件数量排序</p>
            </div>
          </header>
          <AttackDistributionChart :items="store.attackDistribution" />
        </section>
      </div>

      <div class="analysis-grid section-divider">
        <section class="analysis-panel" aria-labelledby="rule-title">
          <header>
            <div>
              <h2 id="rule-title">规则命中 Top 6</h2>
              <p>最常触发的风险判断</p>
            </div>
            <RouterLink class="page-action" to="/investigations">进入调查</RouterLink>
          </header>
          <RuleTopNChart :items="store.ruleDistribution" />
        </section>
        <section class="analysis-panel" aria-labelledby="asr-summary-title">
          <header>
            <div>
              <h2 id="asr-summary-title">防御效果摘要</h2>
              <p>查看阻断、误报和延迟表现</p>
            </div>
            <RouterLink class="page-action" to="/evaluation">查看评测</RouterLink>
          </header>
          <dl class="asr-summary">
            <div>
              <dt>阻断率</dt>
              <dd>{{ formatPercent(store.metrics.blockRate) }}</dd>
            </div>
            <div>
              <dt>误报率 FPR</dt>
              <dd>{{ formatPercent(store.metrics.fpr) }}</dd>
            </div>
            <div>
              <dt>漏报率 FNR</dt>
              <dd>{{ formatPercent(store.metrics.fnr) }}</dd>
            </div>
            <div>
              <dt>平均延迟</dt>
              <dd>
                {{
                  store.metrics.averageLatencyMs === null
                    ? "--"
                    : `${store.metrics.averageLatencyMs.toFixed(1)} ms`
                }}
              </dd>
            </div>
          </dl>
        </section>
      </div>

      <section class="integrity-bar section-divider" aria-labelledby="integrity-bar-title">
        <header>
          <h2 id="integrity-bar-title">审计链完整性</h2>
          <RouterLink class="page-action" to="/system#audit-integrity">查看详情</RouterLink>
        </header>
        <template v-if="store.auditIntegrity">
          <div class="integrity-bar__status">
            <StatusBadge
              :label="store.auditIntegrity.valid ? '审计链有效' : '审计链异常'"
              :tone="store.auditIntegrity.valid ? 'success' : 'danger'"
            />
            <span>{{ store.auditIntegrity.eventCount }} 条审计事件</span>
          </div>
        </template>
        <p v-else class="integrity-bar__empty">暂无完整性数据</p>
      </section>

      <section class="risk-feed section-divider" aria-labelledby="risk-feed-title">
        <header>
          <div>
            <h2 id="risk-feed-title">高风险事件</h2>
            <p>严重与高风险事件按最新时间排列</p>
          </div>
          <RouterLink class="page-action" to="/investigations?severity=high">查看全部</RouterLink>
        </header>
        <div v-if="highRiskEvents.length" class="risk-feed__rows">
          <RouterLink
            v-for="event in highRiskEvents"
            :key="event.id"
            :to="`/evidence/${event.traceId}`"
          >
            <time>{{ event.time }}</time
            ><StatusBadge
              :label="getDecisionLabel(event.decision)"
              :tone="getDecisionTone(event.decision)"
            /><code>{{ event.tool }}</code
            ><span>{{ event.resource }}</span
            ><span class="risk-rail"><i :style="{ width: `${event.riskScore}%` }"></i></span
            ><strong>{{ event.riskScore }}</strong>
          </RouterLink>
        </div>
        <EmptyState v-else title="暂无高风险事件" message="当前数据窗口内没有严重或高风险事件。" />
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import AttackDistributionChart from "../components/charts/AttackDistributionChart.vue";
import RuleTopNChart from "../components/charts/RuleTopNChart.vue";
import DecisionTrendChart from "../components/charts/DecisionTrendChart.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import MetricStrip from "../components/common/MetricStrip.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { getDecisionLabel, getDecisionTone } from "../utils/dashboard-formatters";

defineOptions({ name: "OverviewPage" });
const store = useDashboardStore();
const countFormatter = new Intl.NumberFormat("zh-CN");
const highRiskEvents = computed(() =>
  store.investigationIndex.latestEvents
    .filter((event) => event.severity === "critical" || event.severity === "high")
    .slice(0, 6),
);
const metricItems = computed(() => [
  {
    detail: "当前数据窗口",
    label: "审计事件",
    route: "/investigations",
    value: countFormatter.format(store.metrics.eventCount),
  },
  {
    detail: formatPercent(store.metrics.blockRate),
    label: "已阻断",
    route: "/investigations?blocked=true",
    tone: "protective" as const,
    value: countFormatter.format(store.metrics.blockedCount),
  },
  {
    detail: "需要人工处理",
    label: "待审批",
    route: "/approvals",
    tone: "warning" as const,
    value: countFormatter.format(store.pendingCount),
  },
  {
    detail: "策略允许动作继续",
    label: "已放行",
    route: "/investigations?decision=allow",
    value: countFormatter.format(store.metrics.allowCount),
  },
  {
    detail: "已标注样本",
    label: "误报率 FPR",
    route: "/evaluation",
    value: formatPercent(store.metrics.fpr),
  },
  {
    detail: "安全判定",
    label: "平均延迟",
    route: "/evaluation",
    value:
      store.metrics.averageLatencyMs === null
        ? "--"
        : `${store.metrics.averageLatencyMs.toFixed(1)} ms`,
  },
]);
function formatPercent(value: number | null) {
  return value === null ? "--" : `${(value * 100).toFixed(1)}%`;
}
function handleRefresh() {
  void store.refresh();
}
</script>

<style scoped lang="scss">
.overview-page {
  display: grid;
  gap: var(--space-6);
}
.overview-header {
  margin-bottom: 0;
}
.overview-header__actions {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.overview-header__actions button {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  cursor: pointer;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}
.analysis-grid {
  display: grid;
  gap: clamp(var(--space-6), 4vw, 3rem);
  grid-template-columns: minmax(0, 1.55fr) minmax(min(100%, 18rem), 0.75fr);
}
.analysis-panel {
  display: grid;
  gap: var(--space-5);
  min-width: 0;
}
.analysis-panel > header,
.risk-feed > header {
  align-items: start;
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
}
.analysis-panel h2,
.analysis-panel p,
.risk-feed h2,
.risk-feed p {
  margin: 0;
}
.analysis-panel p,
.risk-feed p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin-top: var(--space-1);
}
.analysis-panel > header .page-action,
.risk-feed > header .page-action {
  font-size: var(--font-size-13);
}
.risk-feed {
  display: grid;
  gap: var(--space-4);
}
.risk-feed__rows {
  display: grid;
}
.risk-feed__rows > a {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  color: var(--color-text);
  display: grid;
  font-size: var(--font-size-13);
  gap: var(--space-3);
  grid-template-columns: 5rem 5rem 8rem minmax(10rem, 1fr) minmax(4rem, 8rem) 2.5rem;
  min-height: 3.5rem;
  padding: 0 var(--space-2);
  text-decoration: none;
}
.risk-feed__rows > a:hover {
  background: var(--color-row-hover);
}
.risk-feed time {
  color: var(--color-text-subtle);
}
.risk-feed__rows span:not(.risk-rail) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.risk-rail {
  background: var(--color-surface-muted);
  height: 0.3rem;
  overflow: hidden;
}
.risk-rail i {
  background: var(--color-danger);
  display: block;
  height: 100%;
}
.risk-feed__rows strong {
  color: var(--color-danger);
  text-align: right;
}
.integrity-bar header {
  align-items: center;
  display: flex;
  justify-content: space-between;
  margin-bottom: var(--space-3);
}
.integrity-bar h2 {
  font-size: var(--font-size-16);
  margin: 0;
}
.integrity-bar__status {
  align-items: center;
  display: flex;
  gap: var(--space-3);
}
.integrity-bar__status span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
}
.integrity-bar__empty {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
  margin: 0;
}
.asr-summary {
  display: grid;
  gap: 1px;
  grid-template-columns: 1fr 1fr;
  margin: 0;
  overflow: hidden;
}
.asr-summary > div {
  background: var(--color-surface-muted);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-3);
}
.asr-summary dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.asr-summary dd {
  font-size: var(--font-size-18);
  font-weight: var(--font-weight-bold);
  margin: 0;
}
@media (max-width: 640px) {
  .risk-feed__rows > a {
    align-items: start;
    grid-template-columns: auto 1fr auto;
    padding: var(--space-3) 0;
  }
  .risk-feed__rows code,
  .risk-feed__rows span:not(.risk-rail) {
    grid-column: 1 / -1;
  }
  .risk-rail {
    grid-column: 1 / 3;
    width: 100%;
  }
}
@media (max-width: 980px) {
  .analysis-grid {
    grid-template-columns: 1fr;
  }
}
</style>
