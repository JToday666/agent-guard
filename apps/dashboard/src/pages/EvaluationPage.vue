<template>
  <section class="evaluation-page workspace-panel" aria-labelledby="evaluation-title">
    <header class="page-header">
      <div><h1 id="evaluation-title">安全评测</h1></div>
      <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
    </header>

    <ErrorState
      v-if="windowUnavailable && !hasRunData"
      :is-retrying="store.isManualRefreshing"
      :message="store.error ?? '近期审计数据加载失败'"
      @retry="store.refresh"
    />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length && !hasRunData" />
    <template v-else>
      <InlineNotice v-if="store.evaluationRunError" title="评测结果暂未更新" tone="warning">
        <p>{{ store.evaluationRunError }}</p>
      </InlineNotice>

      <section v-if="hasRunData" class="benchmark-section" aria-labelledby="benchmark-title">
        <header class="section-header">
          <div>
            <h2 id="benchmark-title">最近一次完整评测</h2>
            <p>{{ store.evaluationRun.datasetLabel }} · 与近期审计数据分开统计</p>
          </div>
          <span>{{ formatMaybeTime(store.evaluationRun.runAt) }}</span>
        </header>

        <div class="benchmark-layout">
          <div class="benchmark-result">
            <dl class="asr-headline" aria-label="防护前后攻击成功率">
              <div>
                <dt>防护前攻击成功率</dt>
                <dd class="asr-headline__before">{{ percent(store.evaluationRun.asrBefore) }}</dd>
              </div>
              <div
                class="asr-headline__change"
                :class="`asr-headline__change--${overallAsrChange.direction}`"
              >
                <dt>{{ overallAsrChange.label }}</dt>
                <dd>{{ overallAsrChange.value }}</dd>
              </div>
              <div>
                <dt>防护后攻击成功率</dt>
                <dd
                  class="asr-headline__after"
                  :class="`asr-headline__after--${overallAsrChange.direction}`"
                >
                  {{ percent(store.evaluationRun.asrAfter) }}
                </dd>
              </div>
            </dl>

            <AsrComparisonChart
              :before="store.evaluationRun.asrBefore"
              :after="store.evaluationRun.asrAfter"
            />

            <dl class="benchmark-facts">
              <div>
                <dt>评测运行 ID</dt>
                <dd>
                  <code>{{ store.evaluationRun.runId }}</code>
                </dd>
              </div>
              <div>
                <dt>数据集版本</dt>
                <dd>{{ store.evaluationRun.datasetVersion ?? "未提供" }}</dd>
              </div>
              <div>
                <dt>样本量</dt>
                <dd>{{ store.evaluationRun.cases.length }}</dd>
              </div>
            </dl>
          </div>

          <section
            v-if="store.evaluationRun.perAttack.length"
            class="attack-asr"
            aria-labelledby="attack-asr-title"
          >
            <header class="section-header">
              <div>
                <h3 id="attack-asr-title">各攻击类型成功率</h3>
                <p>比较防护前后的攻击成功率</p>
              </div>
              <div class="attack-asr__legend" aria-label="图例">
                <span><i class="before"></i>防护前</span>
                <span><i class="after"></i>防护后</span>
              </div>
            </header>
            <div class="attack-asr__rows" role="list">
              <div v-for="row in perAttackRows" :key="row.attackType" role="listitem">
                <div class="attack-asr__label">
                  <strong>{{ getAttackTypeLabel(row.attackType) }}</strong>
                  <span :class="`attack-asr__change--${row.change.direction}`">
                    {{ row.change.text }}
                  </span>
                </div>
                <div class="attack-asr__bars" aria-hidden="true">
                  <i
                    class="before"
                    :style="{ transform: `scaleX(${barScale(row.asrBefore)})` }"
                  ></i>
                  <i class="after" :style="{ transform: `scaleX(${barScale(row.asrAfter)})` }"></i>
                </div>
                <div class="attack-asr__values">
                  <span>{{ percent(row.asrBefore) }}</span>
                  <span>{{ percent(row.asrAfter) }}</span>
                </div>
              </div>
            </div>
          </section>
        </div>
      </section>
      <EmptyState
        v-else
        title="暂无评测结果"
        message="评测结果写入后将在这里展示攻击成功率、防护效果和样本结果。"
      />

      <section class="window-section section-divider" aria-labelledby="window-title">
        <header class="section-header">
          <div>
            <h2 id="window-title">近期安全判断</h2>
            <p>基于已加载记录中去重后的策略判断，与完整评测结果分开统计</p>
          </div>
          <span v-if="!windowUnavailable">
            {{ store.auditWindow.scope.returnedRecordCount }} 条审计记录 ·
            {{ store.windowMetrics.evaluationCount }} 次策略评估 ·
            {{ windowCompletenessLabel }}
          </span>
          <span v-else>窗口数据暂不可用</span>
        </header>
        <InlineNotice v-if="windowUnavailable" title="近期审计数据暂不可用" tone="warning">
          <p>{{ store.error }}</p>
        </InlineNotice>
        <template v-else>
          <MetricStrip :items="metricItems" />

          <details class="window-data-details">
            <summary>查看数据说明</summary>
            <dl>
              <div>
                <dt>数据来源</dt>
                <dd>最近加载的审计记录</dd>
              </div>
              <div>
                <dt>观察范围</dt>
                <dd>{{ windowRangeLabel }}</dd>
              </div>
              <div>
                <dt>完整性</dt>
                <dd>{{ windowCompletenessLabel }}</dd>
              </div>
              <div>
                <dt>去重处理</dt>
                <dd>{{ deduplicationLabel }}</dd>
              </div>
              <div>
                <dt>关联信息</dt>
                <dd>{{ associationLabel }}</dd>
              </div>
              <div>
                <dt>数据覆盖</dt>
                <dd>{{ dataCoverageLabel }}</dd>
              </div>
            </dl>
          </details>

          <div class="window-analysis">
            <ChartFrame
              description="按有耗时记录的安全判断，比较不同运行时的平均判定时间"
              :range-label="windowRangeLabel"
              :summary="runtimeLatencySummary"
              title="运行时判定延迟"
            >
              <div v-if="hasRuntimeData" class="runtime-bars">
                <div v-for="row in runtimeLatency" :key="row.runtime" class="runtime-bar-row">
                  <span class="runtime-bar-label">
                    <strong>{{ getRuntimeLabel(row.runtime) }}</strong>
                    <small>{{ row.count }} 条记录</small>
                  </span>
                  <span class="runtime-bar-track" aria-hidden="true"
                    ><i :style="{ transform: `scaleX(${row.pct / 100})` }"></i
                  ></span>
                  <span class="runtime-bar-val">{{
                    row.avg === null ? "—" : `${row.avg.toFixed(1)} ms`
                  }}</span>
                </div>
              </div>
              <p v-else class="chart-empty">近期数据暂无延迟记录</p>
            </ChartFrame>

            <ChartFrame
              description="根据样本标注与安全策略是否介入计算，不代表工具一定未执行"
              :range-label="windowRangeLabel"
              :summary="matrixSummary"
              title="策略介入混淆矩阵"
            >
              <ConfusionMatrix
                v-if="hasMatrixData"
                :tp="matrix.tp"
                :fp="matrix.fp"
                :tn="matrix.tn"
                :fn="matrix.fn"
              />
              <p v-else class="chart-empty">近期数据暂无足够的恶意标注数据</p>
            </ChartFrame>
          </div>
        </template>
      </section>

      <section class="evaluation-cases section-divider" aria-labelledby="case-title">
        <header class="section-header">
          <div>
            <h2 id="case-title">评测样本</h2>
            <p>完整评测中的样本可追溯到对应证据链</p>
          </div>
          <span>
            {{ store.evaluationRun.cases.length }} 个样本
            <template v-if="totalCasePages > 1">
              · 第 {{ currentCasePage }} / {{ totalCasePages }} 页
            </template>
          </span>
        </header>
        <div
          v-if="selectedCaseId"
          class="case-locator"
          :class="{ 'case-locator--missing': !selectedCaseExists }"
        >
          <span>{{
            selectedCaseExists
              ? `当前定位样本：${selectedCaseId}`
              : `未找到定位样本：${selectedCaseId}`
          }}</span>
          <button type="button" @click="handleClearCaseLocator">清除定位</button>
        </div>
        <template v-if="store.evaluationRun.cases.length">
          <div class="case-table-wrap">
            <table class="case-table">
              <caption>
                评测样本结果
              </caption>
              <thead>
                <tr>
                  <th>样本</th>
                  <th>攻击类型</th>
                  <th>运行时</th>
                  <th>期望</th>
                  <th>实际</th>
                  <th>结果</th>
                  <th>证据链</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="row in paginatedCases"
                  :key="row.caseId"
                  :class="{ 'case-table__selected': selectedCaseId === row.caseId }"
                  :data-case-id="row.caseId"
                >
                  <td>
                    <RouterLink :to="`/evidence/${row.traceId}`"
                      ><code>{{ row.caseId }}</code></RouterLink
                    >
                  </td>
                  <td>{{ getAttackTypeLabel(row.attackType) }}</td>
                  <td>{{ getRuntimeLabel(row.runtime) }}</td>
                  <td>
                    <StatusBadge
                      :label="getDecisionLabel(row.expectedDecision)"
                      :tone="getDecisionTone(row.expectedDecision)"
                    />
                  </td>
                  <td>
                    <StatusBadge
                      :label="getDecisionLabel(row.actualDecision)"
                      :tone="getDecisionTone(row.actualDecision)"
                    />
                  </td>
                  <td>
                    <StatusBadge
                      :label="row.attackSuccess ? '攻击成功' : row.blocked ? '已拦截' : '未成功'"
                      :tone="row.attackSuccess ? 'danger' : 'success'"
                    />
                  </td>
                  <td>
                    <RouterLink :to="`/evidence/${row.traceId}`">{{ row.traceId }}</RouterLink>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <footer v-if="totalCasePages > 1" class="case-pagination" aria-label="评测样本分页">
            <span>第 {{ currentCasePage }} / {{ totalCasePages }} 页</span>
            <div>
              <button
                type="button"
                :disabled="currentCasePage === 1"
                @click="handleCasePage(currentCasePage - 1)"
              >
                上一页
              </button>
              <button
                type="button"
                :disabled="currentCasePage === totalCasePages"
                @click="handleCasePage(currentCasePage + 1)"
              >
                下一页
              </button>
            </div>
          </footer>
        </template>
        <EmptyState v-else title="暂无评测样本" message="完整评测包含样本明细后将在此展示。" />
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import AsrComparisonChart from "../components/charts/AsrComparisonChart.vue";
import ConfusionMatrix from "../components/charts/ConfusionMatrix.vue";
import ChartFrame from "../components/common/ChartFrame.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import InlineNotice from "../components/common/InlineNotice.vue";
import MetricStrip from "../components/common/MetricStrip.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { getAttackTypeLabel } from "../utils/attack-type";
import { describeAsrChange } from "../utils/asr-change";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
  getRuntimeLabel,
} from "../utils/dashboard-formatters";

defineOptions({ name: "EvaluationPage" });

const store = useDashboardStore();
const route = useRoute();
const router = useRouter();
const CASE_PAGE_SIZE = 25;
const countFormatter = new Intl.NumberFormat("zh-CN");
const selectedCaseId = computed(() =>
  typeof route.query.case_id === "string" ? route.query.case_id : "",
);
const selectedCaseExists = computed(() =>
  Boolean(
    selectedCaseId.value &&
    store.evaluationRun.cases.some((row) => row.caseId === selectedCaseId.value),
  ),
);
const requestedCasePage = computed(() => {
  const page = Number.parseInt(
    typeof route.query.case_page === "string" ? route.query.case_page : "1",
    10,
  );
  return Number.isFinite(page) && page > 0 ? page : 1;
});
const totalCasePages = computed(() =>
  Math.max(1, Math.ceil(store.evaluationRun.cases.length / CASE_PAGE_SIZE)),
);
const selectedCasePage = computed(() => {
  if (!selectedCaseId.value) return null;
  const index = store.evaluationRun.cases.findIndex((row) => row.caseId === selectedCaseId.value);
  return index < 0 ? null : Math.floor(index / CASE_PAGE_SIZE) + 1;
});
const currentCasePage = computed(() =>
  Math.min(selectedCasePage.value ?? requestedCasePage.value, totalCasePages.value),
);
const paginatedCases = computed(() =>
  store.evaluationRun.cases.slice(
    (currentCasePage.value - 1) * CASE_PAGE_SIZE,
    currentCasePage.value * CASE_PAGE_SIZE,
  ),
);
const hasRunData = computed(() => store.evaluationRun.runId !== null);
const overallAsrChange = computed(() =>
  describeAsrChange(store.evaluationRun.asrBefore, store.evaluationRun.asrAfter),
);
const perAttackRows = computed(() =>
  store.evaluationRun.perAttack.map((row) => ({
    ...row,
    change: describeAsrChange(row.asrBefore, row.asrAfter),
  })),
);
const windowUnavailable = computed(() => store.status === "error" && Boolean(store.error));
const matrix = computed(() => {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const event of store.policyEvaluations) {
    if (event.isMalicious === null || event.isMalicious === undefined) {
      continue;
    }
    const intervened = event.decision === "ask" || event.decision === "deny";
    if (event.decision === "unknown") continue;
    if (event.isMalicious && intervened) tp++;
    else if (!event.isMalicious && intervened) fp++;
    else if (!event.isMalicious && !intervened) tn++;
    else if (event.isMalicious && !intervened) fn++;
  }
  return { tp, fp, tn, fn };
});
const hasMatrixData = computed(
  () => matrix.value.tp + matrix.value.fp + matrix.value.tn + matrix.value.fn > 0,
);
const labeledEvaluationCount = computed(
  () => store.windowMetrics.benignLabelCount + store.windowMetrics.maliciousLabelCount,
);
const windowRangeLabel = computed(() => {
  const { from, to } = store.auditWindow.scope;
  if (!from || !to) return "近期审计数据";
  return `${formatDashboardDateTime(from)} 至 ${formatDashboardDateTime(to)}`;
});
const windowCompletenessLabel = computed(() => {
  if (store.auditWindow.scope.hasMore === true) return "仅显示部分记录";
  if (store.auditWindow.scope.hasMore === false) return "近期记录完整";
  return "是否截断未知";
});
const deduplicationLabel = computed(() =>
  store.windowMetrics.duplicatePolicyRecordCount
    ? `已合并 ${store.windowMetrics.duplicatePolicyRecordCount} 条重复策略记录`
    : "未发现重复策略记录",
);
const associationLabel = computed(() =>
  store.windowMetrics.legacyFallbackCount
    ? `${store.windowMetrics.legacyFallbackCount} 条较早记录缺少关联标识，按单条记录统计`
    : "用于去重的关联信息完整",
);
const dataCoverageLabel = computed(() => {
  const unknown = store.windowMetrics.unknownDecisionCount;
  const unlabeled = store.windowMetrics.unlabeledCount;
  if (!unknown && !unlabeled) return "决定与样本标注均有记录";
  return `${unknown} 次判断缺少明确决定；${unlabeled} 次评估缺少样本标注`;
});
const metricItems = computed(() => [
  {
    detail: `最近加载，上限 ${store.auditWindow.scope.limit} 条；${windowCompletenessLabel.value}`,
    label: "审计记录",
    route: "/investigations",
    value: countFormatter.format(store.auditWindow.scope.returnedRecordCount),
  },
  {
    detail: `${labeledEvaluationCount.value} 次评估含可用恶意性标注`,
    label: "策略评估",
    route: "/investigations",
    value: countFormatter.format(store.windowMetrics.evaluationCount),
  },
  {
    detail: `拒绝率 ${percent(store.windowMetrics.policyDenyRate)} · 审批触发率 ${percent(store.windowMetrics.approvalTriggerRate)}`,
    label: "策略介入率",
    route: "/investigations",
    tone: "protective" as const,
    value: percent(store.windowMetrics.interventionRate),
  },
  {
    detail: `分母为 ${store.windowMetrics.benignLabelCount} 个正常标注评估`,
    label: "策略误报率",
    route: "/investigations",
    value: percent(store.windowMetrics.policyFpr),
  },
  {
    detail: `分母为 ${store.windowMetrics.maliciousLabelCount} 个恶意标注评估`,
    label: "策略漏报率",
    route: "/investigations?decision=allow",
    tone: "danger" as const,
    value: percent(store.windowMetrics.policyFnr),
  },
  {
    detail: `${store.windowMetrics.latencySampleCount} 次策略判定有耗时记录`,
    label: "平均判定延迟",
    route: "/system",
    value:
      store.windowMetrics.averageDecisionLatencyMs === null
        ? "--"
        : `${store.windowMetrics.averageDecisionLatencyMs.toFixed(1)} ms`,
  },
]);
const runtimeLatency = computed(() => {
  const runtimes = ["langgraph", "openclaw"] as const;
  const rows = runtimes.map((runtime) => {
    const values = store.policyEvaluations
      .filter((event) => event.runtime === runtime && event.latencyMs != null)
      .map((event) => event.latencyMs as number);
    const avg = values.length
      ? values.reduce((sum, value) => sum + value, 0) / values.length
      : null;
    return { runtime, avg, count: values.length };
  });
  const max = Math.max(1, ...rows.map((row) => row.avg ?? 0));
  return rows.map((row) => ({ ...row, pct: row.avg ? (row.avg / max) * 100 : 0 }));
});
const hasRuntimeData = computed(() => runtimeLatency.value.some((row) => row.avg !== null));
const runtimeLatencySummary = computed(() => {
  const rows = runtimeLatency.value.filter((row) => row.avg !== null);
  return rows.length
    ? rows
        .map((row) => `${getRuntimeLabel(row.runtime)} 平均 ${row.avg!.toFixed(1)} 毫秒`)
        .join("，")
    : "近期数据暂无延迟记录";
});
const matrixSummary = computed(() =>
  hasMatrixData.value
    ? `共 ${labeledEvaluationCount.value} 次已标注策略评估，正确介入 ${matrix.value.tp}，误报 ${matrix.value.fp}，正确未介入 ${matrix.value.tn}，漏报 ${matrix.value.fn}`
    : "近期数据暂无足够的恶意标注数据",
);

function percent(value: number | null): string {
  return value === null ? "--" : `${(value * 100).toFixed(1)}%`;
}

function barScale(value: number | null): number {
  return value === null ? 0 : Math.max(0.02, Math.min(1, value));
}

function formatMaybeTime(value: string | null): string {
  return value ? formatDashboardDateTime(value) : "未提供";
}

function handleClearCaseLocator() {
  void router.replace({
    path: "/evaluation",
    query: currentCasePage.value > 1 ? { case_page: currentCasePage.value } : {},
  });
}

function handleCasePage(page: number) {
  void router.replace({
    path: "/evaluation",
    query: page > 1 ? { case_page: page } : {},
  });
}

watch(
  [selectedCaseId, () => store.evaluationRun.cases.length],
  async ([caseId]) => {
    if (!caseId) return;
    await nextTick();
    document.querySelector(`[data-case-id="${CSS.escape(caseId)}"]`)?.scrollIntoView({
      block: "center",
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    });
  },
  { immediate: true },
);
</script>

<style scoped lang="scss">
.evaluation-page {
  display: grid;
  gap: var(--space-6);
}
.benchmark-section,
.window-section,
.evaluation-cases {
  display: grid;
  gap: var(--space-5);
}
.benchmark-section {
  border-block: 1px solid var(--color-border);
  padding: var(--space-5) 0;
}
.benchmark-section > header > span,
.window-section > header > span,
.evaluation-cases > header > span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.benchmark-layout {
  display: grid;
  gap: clamp(var(--space-6), 3vw, var(--space-8));
  grid-template-columns: minmax(0, 1.08fr) minmax(24rem, 0.92fr);
}
.benchmark-result {
  display: grid;
  gap: var(--space-4);
  min-width: 0;
}
.asr-headline {
  align-items: end;
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
  margin: 0;
}
.asr-headline > div {
  min-width: 0;
}
.asr-headline dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
}
.asr-headline dd {
  font-size: clamp(2.2rem, 4vw, 3.4rem);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-bold);
  letter-spacing: -0.045em;
  line-height: 0.95;
  margin: var(--space-1) 0 0;
}
.asr-headline__before {
  color: var(--color-danger);
}
.asr-headline__after {
  color: var(--color-text-muted);
  text-align: right;
}
.asr-headline__after--decrease {
  color: var(--color-success);
}
.asr-headline__after--increase {
  color: var(--color-danger);
}
.asr-headline > div:last-child dt {
  text-align: right;
}
.asr-headline__change {
  border-inline: 1px solid var(--color-border);
  min-width: 7rem !important;
  padding-inline: var(--space-4);
  text-align: center;
}
.asr-headline__change dd {
  color: var(--color-text-muted);
  font-size: var(--font-size-24);
  letter-spacing: -0.025em;
}
.asr-headline__change--decrease dd {
  color: var(--color-success);
}
.asr-headline__change--increase dd {
  color: var(--color-danger);
}
.benchmark-facts {
  display: grid;
  gap: 1px;
  grid-template-columns: 1.2fr 0.8fr 0.55fr;
  margin: 0;
  overflow: hidden;
}
.benchmark-facts > div {
  background: var(--color-surface-muted);
  min-width: 0;
  padding: var(--space-3);
}
.benchmark-facts dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.benchmark-facts dd {
  font-size: var(--font-size-12);
  margin: var(--space-1) 0 0;
  overflow-wrap: anywhere;
}
.window-section {
  padding-top: var(--space-6);
}
.window-analysis {
  display: grid;
  gap: clamp(var(--space-6), 3vw, var(--space-8));
  grid-template-columns: minmax(0, 1fr) minmax(25rem, 0.8fr);
}
.chart-empty {
  color: var(--color-text-subtle);
  display: grid;
  font-size: var(--font-size-13);
  min-height: 10rem;
  margin: 0;
  place-items: center;
}
.attack-asr {
  display: grid;
  gap: var(--space-4);
  min-width: 0;
}
.attack-asr h3,
.attack-asr p,
.evaluation-cases p {
  margin: 0;
}
.attack-asr h3 {
  font-size: var(--font-size-16);
}
.attack-asr p,
.evaluation-cases p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin-top: var(--space-1);
}
.attack-asr__legend {
  align-items: center;
  color: var(--color-text-subtle);
  display: flex;
  font-size: var(--font-size-11);
  gap: var(--space-3);
}
.attack-asr__legend span {
  align-items: center;
  display: inline-flex;
  gap: var(--space-1);
}
.attack-asr__legend i {
  display: inline-block;
  height: 0.45rem;
  width: 0.9rem;
}
.attack-asr__legend .before {
  background: var(--color-danger);
}
.attack-asr__legend .after {
  background: var(--color-success);
}
.attack-asr__rows {
  border-top: 1px solid var(--color-border);
  display: grid;
}
.attack-asr__rows > div {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(8rem, 0.9fr) minmax(9rem, 1.5fr) 5.5rem;
  min-height: 3.7rem;
  padding: var(--space-2);
}
.attack-asr__label {
  display: grid;
  gap: var(--space-1);
  min-width: 0;
}
.attack-asr__label strong {
  overflow-wrap: anywhere;
}
.attack-asr__label span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
}
.attack-asr__label .attack-asr__change--decrease {
  color: var(--color-success);
}
.attack-asr__label .attack-asr__change--increase {
  color: var(--color-danger);
}
.attack-asr__label .attack-asr__change--unchanged {
  color: var(--color-text-muted);
}
.attack-asr__bars {
  display: grid;
  gap: 0.35rem;
}
.attack-asr__bars i {
  display: block;
  height: 0.45rem;
  min-width: 2px;
  transform-origin: left;
  transition: transform var(--transition-data);
  width: 100%;
}
.attack-asr__bars .before {
  background: var(--gradient-data-danger);
}
.attack-asr__bars .after {
  background: var(--gradient-data-active);
}
.attack-asr__values {
  color: var(--color-text-muted);
  display: flex;
  font-size: var(--font-size-12);
  font-variant-numeric: tabular-nums;
  justify-content: space-between;
}
.runtime-bars {
  display: grid;
  gap: var(--space-3);
}
.window-data-details {
  border-block: 1px solid var(--color-border);
}
.window-data-details summary {
  align-items: center;
  color: var(--color-link);
  cursor: pointer;
  display: flex;
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  min-height: 2.25rem;
  width: fit-content;
}
.window-data-details summary:hover {
  color: var(--color-active);
}
.window-data-details dl {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin: 0;
  padding: var(--space-2) 0 var(--space-4);
}
.window-data-details dl > div {
  border-left: 1px solid var(--color-border);
  min-width: 0;
  padding: var(--space-2) var(--space-4);
}
.window-data-details dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.window-data-details dd {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  margin: var(--space-1) 0 0;
  overflow-wrap: anywhere;
}
.runtime-bar-row {
  align-items: center;
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 7rem 1fr 5rem;
  min-height: 3.5rem;
}
.runtime-bar-label {
  display: grid;
  gap: 0.1rem;
}
.runtime-bar-label strong {
  font-size: var(--font-size-13);
}
.runtime-bar-label small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.runtime-bar-track {
  background: var(--color-surface-muted);
  border-radius: 3px;
  height: 0.5rem;
  overflow: hidden;
}
.runtime-bar-track i {
  background: var(--gradient-data-warning);
  border-radius: inherit;
  display: block;
  height: 100%;
  min-width: 3px;
  transform-origin: left;
  transition: transform var(--transition-data);
  width: 100%;
}
.runtime-bar-val {
  color: var(--color-text-muted);
  font-size: var(--font-size-13);
  font-variant-numeric: tabular-nums;
  text-align: right;
}
.case-locator {
  align-items: center;
  background: var(--color-active-soft);
  border: 1px solid var(--color-active-border);
  border-radius: var(--radius-2);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  justify-content: space-between;
  padding: var(--space-3);
}
.case-locator span {
  color: var(--color-active);
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  overflow-wrap: anywhere;
}
.case-locator button {
  background: var(--color-surface);
  border: 1px solid var(--color-active-border);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}
.case-locator--missing {
  background: var(--color-warning-soft);
  border-color: var(--color-warning-border);
}
.case-locator--missing span {
  color: var(--color-warning);
}
.case-table-wrap {
  overflow: auto;
}
.case-table {
  border-collapse: collapse;
  min-width: 48rem;
  width: 100%;
}
.case-table caption {
  clip: rect(0, 0, 0, 0);
  height: 1px;
  overflow: hidden;
  position: absolute;
  width: 1px;
}
.case-table th,
.case-table td {
  border-bottom: 1px solid var(--color-border);
  font-size: var(--font-size-13);
  padding: var(--space-3);
  text-align: left;
  vertical-align: middle;
}
.case-table th {
  background: var(--color-surface);
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  letter-spacing: 0;
  position: sticky;
  top: 0;
  z-index: 1;
}
.case-table__selected {
  background: var(--color-active-soft);
  box-shadow: inset 2px 0 var(--color-active);
}
.case-pagination {
  align-items: center;
  color: var(--color-text-muted);
  display: flex;
  font-size: var(--font-size-12);
  justify-content: space-between;
}
.case-pagination div {
  display: flex;
  gap: var(--space-2);
}
.case-pagination button {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  cursor: pointer;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}
.case-pagination button:disabled {
  cursor: default;
  opacity: 0.45;
}

@media (max-width: 56.25rem) {
  .benchmark-layout,
  .window-analysis {
    grid-template-columns: 1fr;
  }

  .benchmark-facts,
  .window-data-details dl {
    grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
  }

  .case-pagination {
    flex-wrap: wrap;
    gap: var(--space-3);
  }

  .case-table-wrap {
    max-width: 100%;
    overscroll-behavior-inline: contain;
  }
}
</style>
