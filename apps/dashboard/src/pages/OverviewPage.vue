<template>
  <section class="overview-page workspace-panel" aria-labelledby="overview-title">
    <header class="page-header overview-header">
      <div><h1 id="overview-title">安全总览</h1></div>
      <div class="overview-header__actions">
        <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
        <button
          class="page-action"
          type="button"
          :aria-busy="store.isManualRefreshing"
          :disabled="store.isManualRefreshing"
          @click="handleRefresh"
        >
          <RefreshCw
            aria-hidden="true"
            :class="{ 'is-spinning': store.isManualRefreshing }"
            :size="15"
          />
          {{ store.isManualRefreshing ? "刷新中…" : "刷新数据" }}
        </button>
      </div>
    </header>

    <ErrorState
      v-if="store.status === 'error' && store.error"
      :is-retrying="store.isManualRefreshing"
      :message="store.error"
      @retry="handleRefresh"
    />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" :rows="6" />
    <template v-else>
      <MetricStrip :items="metricItems" />

      <div class="overview-primary section-divider">
        <ChartFrame
          class="overview-trend"
          description="Guard 决策随当前审计窗口变化"
          :range-label="windowRangeLabel"
          :summary="trendSummary"
          title="决策趋势"
        >
          <template #controls>
            <RouterLink class="chart-link" to="/investigations">进入调查</RouterLink>
          </template>
          <DecisionTrendChart :points="store.decisionTrend" />
        </ChartFrame>

        <section class="triage-queue" aria-labelledby="triage-title">
          <header class="section-header">
            <div>
              <h2 id="triage-title">待分诊</h2>
              <p>优先处理待审批与高风险事件</p>
            </div>
            <RouterLink class="chart-link" to="/investigations?severity=high">查看全部</RouterLink>
          </header>
          <div v-if="triageItems.length" class="triage-queue__rows">
            <RouterLink v-for="item in triageItems" :key="item.id" :to="item.to">
              <span class="triage-queue__signal" :class="`triage-queue__signal--${item.tone}`">
                {{ item.kind }}
              </span>
              <strong>{{ item.tool }}</strong>
              <span class="triage-queue__resource" :title="item.resource">{{ item.resource }}</span>
              <span class="triage-queue__risk">
                <i
                  :style="{
                    transform: `scaleX(${Math.min(1, Math.max(0, (item.riskScore ?? 0) / 100))})`,
                  }"
                ></i>
              </span>
              <b
                ><span>{{ item.riskScore ?? "--" }}</span
                ><small>{{ getRiskSeverityLabel(item.severity) }}</small></b
              >
            </RouterLink>
          </div>
          <EmptyState
            v-else
            title="当前无需分诊"
            message="当前审计窗口内没有待审批或高风险事件。"
          />
        </section>
      </div>

      <div class="overview-secondary section-divider">
        <ChartFrame
          description="识别当前窗口中的主要攻击面"
          :range-label="windowRangeLabel"
          :summary="`攻击类型分布，共 ${store.attackDistribution.length} 类`"
          title="攻击类型"
        >
          <AttackDistributionChart :items="store.attackDistribution" />
        </ChartFrame>
        <ChartFrame
          description="定位最常触发的风险判断"
          :range-label="windowRangeLabel"
          :summary="`规则命中排行，共 ${store.ruleDistribution.length} 项`"
          title="规则命中 Top 6"
        >
          <template #controls>
            <RouterLink class="chart-link" to="/investigations">查看事件</RouterLink>
          </template>
          <RuleTopNChart :items="store.ruleDistribution" />
        </ChartFrame>
        <section class="defense-ledger" aria-labelledby="defense-ledger-title">
          <header class="section-header">
            <div>
              <h2 id="defense-ledger-title">防御效果</h2>
              <p>当前窗口中的逻辑唯一策略评估</p>
            </div>
            <RouterLink class="chart-link" to="/evaluation">查看评测</RouterLink>
          </header>
          <dl>
            <div>
              <dt>策略介入率</dt>
              <dd>{{ formatPercent(store.windowMetrics.interventionRate) }}</dd>
            </div>
            <div>
              <dt>误报率 FPR</dt>
              <dd>{{ formatPercent(store.windowMetrics.policyFpr) }}</dd>
            </div>
            <div>
              <dt>漏报率 FNR</dt>
              <dd>{{ formatPercent(store.windowMetrics.policyFnr) }}</dd>
            </div>
            <div>
              <dt>平均延迟</dt>
              <dd>{{ formatLatency(store.windowMetrics.averageDecisionLatencyMs) }}</dd>
            </div>
          </dl>
        </section>
      </div>

      <section class="integrity-bar section-divider" aria-labelledby="integrity-bar-title">
        <header class="section-header">
          <div>
            <h2 id="integrity-bar-title">审计链完整性</h2>
            <p>确认当前证据链是否连续且可验证</p>
          </div>
          <RouterLink class="chart-link" to="/system#audit-integrity">查看详情</RouterLink>
        </header>
        <div v-if="store.auditIntegrity" class="integrity-bar__status">
          <StatusBadge
            :label="store.auditIntegrity.valid ? '审计链有效' : '审计链异常'"
            :tone="store.auditIntegrity.valid ? 'success' : 'danger'"
          />
          <span>{{ store.auditIntegrity.eventCount }} 条审计事件</span>
          <code>{{ formatAuditHeadHash(store.auditIntegrity.headHash) }}</code>
        </div>
        <InlineNotice
          v-else-if="store.auditIntegrityError"
          title="完整性状态暂不可用"
          tone="warning"
        >
          <p>{{ store.auditIntegrityError }}</p>
        </InlineNotice>
        <p v-else class="integrity-bar__empty">正在读取审计完整性状态…</p>
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { RefreshCw } from "@lucide/vue";
import { computed } from "vue";

import AttackDistributionChart from "../components/charts/AttackDistributionChart.vue";
import DecisionTrendChart from "../components/charts/DecisionTrendChart.vue";
import RuleTopNChart from "../components/charts/RuleTopNChart.vue";
import ChartFrame from "../components/common/ChartFrame.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import InlineNotice from "../components/common/InlineNotice.vue";
import MetricStrip from "../components/common/MetricStrip.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import {
  formatAuditHeadHash,
  formatDashboardDateTime,
  getRiskSeverityLabel,
} from "../utils/dashboard-formatters";

defineOptions({ name: "OverviewPage" });

const store = useDashboardStore();
const countFormatter = new Intl.NumberFormat("zh-CN");

const triageItems = computed(() => {
  const approvalItems = [...store.approvals]
    .sort((left, right) => right.riskScore - left.riskScore)
    .slice(0, 2)
    .map((approval) => ({
      id: `approval-${approval.id}`,
      kind: "待审批",
      resource: approval.resource,
      riskScore: approval.riskScore,
      severity: approval.severity,
      tone: "warning" as const,
      tool: approval.tool,
      to: `/approvals/${approval.id}`,
    }));
  const approvalEventIds = new Set(store.approvals.map((approval) => approval.eventId));
  const eventItems = [...store.policyEvaluations]
    .sort((left, right) => Date.parse(right.occurredAt) - Date.parse(left.occurredAt))
    .filter(
      (event) =>
        !approvalEventIds.has(event.id) &&
        (event.severity === "critical" || event.severity === "high"),
    )
    .slice(0, Math.max(0, 5 - approvalItems.length))
    .map((event) => ({
      id: `event-${event.id}`,
      kind: "高风险",
      resource: event.resource,
      riskScore: event.riskScore,
      severity: event.severity,
      tone: "danger" as const,
      tool: event.tool,
      to: `/evidence/${event.traceId}?event_id=${event.id}`,
    }));
  return [...approvalItems, ...eventItems];
});

const trendSummary = computed(() => {
  const latest = store.decisionTrend.at(-1);
  return latest
    ? `最新时间段允许 ${latest.allow}，需审批 ${latest.ask}，拒绝 ${latest.deny}`
    : "当前没有可绘制的决策趋势";
});

const windowRangeLabel = computed(() => {
  const { from, to } = store.auditWindow.scope;
  if (!from || !to) return "当前审计窗口";
  return `${formatDashboardDateTime(from)} 至 ${formatDashboardDateTime(to)}`;
});
const windowCompletenessLabel = computed(() => {
  if (store.auditWindow.scope.hasMore === true) return "仅显示部分记录";
  if (store.auditWindow.scope.hasMore === false) return "当前窗口记录完整";
  return "是否截断未知";
});

const metricItems = computed(() => [
  {
    detail: `最近加载，上限 ${store.auditWindow.scope.limit} 条；${windowCompletenessLabel.value}`,
    label: "审计记录",
    route: "/investigations",
    value: countFormatter.format(store.auditWindow.scope.returnedRecordCount),
  },
  {
    detail: `策略拒绝率 ${formatPercent(store.windowMetrics.policyDenyRate)}`,
    label: "策略拒绝",
    route: "/investigations?decision=deny",
    tone: "protective" as const,
    value: countFormatter.format(store.windowMetrics.denyCount),
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
    label: "允许",
    route: "/investigations?decision=allow",
    value: countFormatter.format(store.windowMetrics.allowCount),
  },
  {
    detail: `${store.windowMetrics.benignLabelCount} 个正常标注评估`,
    label: "策略误报率 FPR",
    route: "/evaluation",
    value: formatPercent(store.windowMetrics.policyFpr),
  },
  {
    detail: `${store.windowMetrics.latencySampleCount} 次判定有耗时记录`,
    label: "平均判定延迟",
    route: "/evaluation",
    value: formatLatency(store.windowMetrics.averageDecisionLatencyMs),
  },
]);

function formatPercent(value: number | null) {
  return value === null ? "--" : `${(value * 100).toFixed(1)}%`;
}

function formatLatency(value: number | null) {
  return value === null ? "--" : `${value.toFixed(1)} ms`;
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

.overview-header__actions button:disabled {
  cursor: wait;
  opacity: 0.65;
}

.is-spinning {
  animation: overview-spin 0.8s linear infinite;
}

@keyframes overview-spin {
  to {
    transform: rotate(360deg);
  }
}

.overview-primary {
  display: grid;
  gap: clamp(var(--space-6), 3vw, var(--space-8));
  grid-template-columns: minmax(0, 1.6fr) minmax(19rem, 0.8fr);
}

.overview-trend {
  min-width: 0;
}

.chart-link {
  color: var(--color-link);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  text-decoration: none;
  white-space: nowrap;

  &:hover {
    text-decoration: underline;
  }
}

.triage-queue {
  display: grid;
  gap: var(--space-4);
  min-width: 0;
}

.triage-queue__rows {
  border-top: 1px solid var(--color-border);
  display: grid;
}

.triage-queue__rows > a {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  color: var(--color-text);
  display: grid;
  font-size: var(--font-size-12);
  gap: var(--space-2);
  grid-template-columns: auto minmax(5rem, 0.7fr) minmax(6rem, 1fr) minmax(3rem, 0.55fr) 2rem;
  min-height: 3.25rem;
  padding: var(--space-2);
  text-decoration: none;

  &:hover {
    background: var(--color-row-hover);
  }
}

.triage-queue__signal {
  border-left: 2px solid currentColor;
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
  padding-left: var(--space-2);
  white-space: nowrap;

  &--warning {
    color: var(--color-warning);
  }

  &--danger {
    color: var(--color-danger);
  }
}

.triage-queue__rows strong,
.triage-queue__resource {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.triage-queue__risk {
  background: var(--color-surface-inset);
  border-radius: var(--radius-pill);
  height: 0.3rem;
  overflow: hidden;

  i {
    background: var(--gradient-data-danger);
    display: block;
    height: 100%;
    transform-origin: left;
    transition: transform var(--transition-data);
    width: 100%;
  }
}

.triage-queue__rows b {
  align-items: end;
  color: var(--color-danger);
  display: grid;
  font-variant-numeric: tabular-nums;
  text-align: right;
}

.triage-queue__rows b small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-medium);
}

.overview-secondary {
  display: grid;
  gap: clamp(var(--space-6), 3vw, var(--space-8));
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.defense-ledger {
  display: grid;
  gap: var(--space-4);
}

.defense-ledger dl {
  border-top: 1px solid var(--color-border);
  display: grid;
  margin: 0;
}

.defense-ledger dl > div {
  align-items: baseline;
  border-bottom: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-3);
  justify-content: space-between;
  min-height: 3.1rem;
  padding: var(--space-2);
}

.defense-ledger dt {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
}

.defense-ledger dd {
  font-size: var(--font-size-20);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-bold);
  margin: 0;
}

.integrity-bar {
  display: grid;
  gap: var(--space-4);
}

.integrity-bar__status {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}

.integrity-bar__status > span,
.integrity-bar__empty {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
}

.integrity-bar__status code {
  color: var(--color-text-muted);
}

.integrity-bar__empty {
  margin: 0;
}

@media (max-width: 82rem) {
  .overview-primary {
    grid-template-columns: minmax(0, 1.45fr) minmax(17rem, 0.75fr);
  }

  .overview-secondary {
    gap: var(--space-6);
  }
}
</style>
