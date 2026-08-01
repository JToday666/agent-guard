<template>
  <section class="evaluation-page workspace-panel" aria-labelledby="evaluation-title">
    <header class="page-header">
      <div><h1 id="evaluation-title">安全评测</h1></div>
      <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
    </header>

    <ErrorState
      v-if="store.status === 'error' && store.error"
      :is-retrying="store.isRefreshing"
      :message="store.error"
      @retry="store.refresh"
    />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
    <template v-else>
      <InlineNotice v-if="store.evaluationError" title="评测结果暂未更新" tone="warning">
        <p>{{ store.evaluationError }}</p>
      </InlineNotice>

      <section v-if="hasRunData" class="benchmark-section" aria-labelledby="benchmark-title">
        <header class="section-header">
          <div>
            <h2 id="benchmark-title">完整评测结果</h2>
            <p>{{ store.evaluation.datasetLabel }} · 独立评测运行</p>
          </div>
          <span>{{ formatMaybeTime(store.evaluation.runAt) }}</span>
        </header>

        <div class="benchmark-layout">
          <div class="benchmark-result">
            <dl class="asr-headline" aria-label="防护前后攻击成功率">
              <div>
                <dt>防护前 ASR</dt>
                <dd class="asr-headline__before">{{ percent(store.evaluation.asrBefore) }}</dd>
              </div>
              <div class="asr-headline__change">
                <dt>ASR 降幅</dt>
                <dd>{{ pointDelta(store.evaluation.asrBefore, store.evaluation.asrAfter) }}</dd>
              </div>
              <div>
                <dt>防护后 ASR</dt>
                <dd class="asr-headline__after">{{ percent(store.evaluation.asrAfter) }}</dd>
              </div>
            </dl>

            <AsrComparisonChart
              :before="store.evaluation.asrBefore"
              :after="store.evaluation.asrAfter"
            />

            <dl class="benchmark-facts">
              <div>
                <dt>运行 ID</dt>
                <dd>
                  <code>{{ store.evaluation.runId }}</code>
                </dd>
              </div>
              <div>
                <dt>数据集版本</dt>
                <dd>{{ store.evaluation.datasetVersion ?? "未提供" }}</dd>
              </div>
              <div>
                <dt>样本量</dt>
                <dd>{{ store.evaluation.cases.length }}</dd>
              </div>
            </dl>
          </div>

          <section
            v-if="store.evaluation.perAttack.length"
            class="attack-asr"
            aria-labelledby="attack-asr-title"
          >
            <header class="section-header">
              <div>
                <h3 id="attack-asr-title">攻击类型 ASR</h3>
                <p>按防护前攻击成功率对比防护效果</p>
              </div>
              <div class="attack-asr__legend" aria-label="图例">
                <span><i class="before"></i>防护前</span>
                <span><i class="after"></i>防护后</span>
              </div>
            </header>
            <div class="attack-asr__rows" role="list">
              <div v-for="row in store.evaluation.perAttack" :key="row.attackType" role="listitem">
                <div class="attack-asr__label">
                  <strong>{{ row.attackType }}</strong>
                  <span>下降 {{ pointDelta(row.asrBefore, row.asrAfter) }}</span>
                </div>
                <div class="attack-asr__bars" aria-hidden="true">
                  <i class="before" :style="{ width: barWidth(row.asrBefore) }"></i>
                  <i class="after" :style="{ width: barWidth(row.asrAfter) }"></i>
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
            <h2 id="window-title">当前审计窗口</h2>
            <p>由当前加载的审计事件实时派生，不与完整评测结果混算</p>
          </div>
          <span>{{ store.events.length }} 条事件 · {{ labeledEventCount }} 条已标注</span>
        </header>
        <MetricStrip :items="metricItems" />

        <div class="window-analysis">
          <ChartFrame
            description="按有延迟记录的审计事件计算运行时均值"
            :summary="runtimeLatencySummary"
            title="运行时判定延迟"
          >
            <div v-if="hasRuntimeData" class="runtime-bars">
              <div v-for="row in runtimeLatency" :key="row.runtime" class="runtime-bar-row">
                <span class="runtime-bar-label">
                  <strong>{{ row.runtime }}</strong>
                  <small>{{ row.count }} 条记录</small>
                </span>
                <span class="runtime-bar-track" aria-hidden="true"
                  ><i :style="{ width: `${row.pct}%` }"></i
                ></span>
                <span class="runtime-bar-val">{{
                  row.avg === null ? "—" : `${row.avg.toFixed(1)} ms`
                }}</span>
              </div>
            </div>
            <p v-else class="chart-empty">当前窗口暂无延迟记录</p>
          </ChartFrame>

          <ChartFrame
            description="由恶意标注与实际阻断结果派生"
            :summary="matrixSummary"
            title="混淆矩阵"
          >
            <ConfusionMatrix
              v-if="hasMatrixData"
              :tp="matrix.tp"
              :fp="matrix.fp"
              :tn="matrix.tn"
              :fn="matrix.fn"
            />
            <p v-else class="chart-empty">当前窗口暂无足够的恶意标注数据</p>
          </ChartFrame>
        </div>
      </section>

      <section class="evaluation-cases section-divider" aria-labelledby="case-title">
        <header class="section-header">
          <div>
            <h2 id="case-title">评测样本</h2>
            <p>完整评测中的样本可追溯到对应证据链</p>
          </div>
          <span>{{ store.evaluation.cases.length }} 个样本</span>
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
        <div v-if="store.evaluation.cases.length" class="case-table-wrap">
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
                v-for="row in store.evaluation.cases"
                :key="row.caseId"
                :class="{ 'case-table__selected': selectedCaseId === row.caseId }"
                :data-case-id="row.caseId"
              >
                <td>
                  <RouterLink :to="`/evidence/${row.traceId}`"
                    ><code>{{ row.caseId }}</code></RouterLink
                  >
                </td>
                <td>{{ row.attackType }}</td>
                <td>{{ row.runtime }}</td>
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
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
} from "../utils/dashboard-formatters";

defineOptions({ name: "EvaluationPage" });

const store = useDashboardStore();
const route = useRoute();
const router = useRouter();
const countFormatter = new Intl.NumberFormat("zh-CN");
const selectedCaseId = computed(() =>
  typeof route.query.case_id === "string" ? route.query.case_id : "",
);
const selectedCaseExists = computed(() =>
  Boolean(
    selectedCaseId.value &&
    store.evaluation.cases.some((row) => row.caseId === selectedCaseId.value),
  ),
);
const hasRunData = computed(() => store.evaluation.runId !== null);
const matrix = computed(() => {
  const events = store.events;
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const event of events) {
    if (event.isMalicious === null || event.isMalicious === undefined) continue;
    if (event.isMalicious && event.blocked) tp++;
    else if (!event.isMalicious && event.blocked) fp++;
    else if (!event.isMalicious && !event.blocked) tn++;
    else if (event.isMalicious && !event.blocked) fn++;
  }
  return { tp, fp, tn, fn };
});
const hasMatrixData = computed(
  () => matrix.value.tp + matrix.value.fp + matrix.value.tn + matrix.value.fn > 0,
);
const labeledEventCount = computed(
  () =>
    store.events.filter((event) => event.isMalicious !== null && event.isMalicious !== undefined)
      .length,
);
const metricItems = computed(() => [
  {
    detail: "当前加载数据",
    label: "审计事件",
    route: "/investigations",
    value: countFormatter.format(store.metrics.eventCount),
  },
  {
    detail: "含恶意性标注",
    label: "已标注样本",
    route: "/investigations",
    value: countFormatter.format(labeledEventCount.value),
  },
  {
    detail: "实际执行阻断",
    label: "阻断率",
    route: "/investigations?blocked=true",
    tone: "protective" as const,
    value: percent(store.metrics.blockRate),
  },
  {
    detail: "正常样本被阻断",
    label: "误报率 FPR",
    route: "/investigations",
    value: percent(store.metrics.fpr),
  },
  {
    detail: "恶意样本未阻断",
    label: "漏报率 FNR",
    route: "/investigations?decision=allow",
    tone: "danger" as const,
    value: percent(store.metrics.fnr),
  },
  {
    detail: "有耗时记录的事件",
    label: "平均判定延迟",
    route: "/system",
    value:
      store.metrics.averageLatencyMs === null
        ? "--"
        : `${store.metrics.averageLatencyMs.toFixed(1)} ms`,
  },
]);
const runtimeLatency = computed(() => {
  const runtimes = ["langgraph", "openclaw"] as const;
  const rows = runtimes.map((runtime) => {
    const values = store.events
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
    ? rows.map((row) => `${row.runtime} 平均 ${row.avg!.toFixed(1)} 毫秒`).join("，")
    : "当前窗口暂无延迟记录";
});
const matrixSummary = computed(() =>
  hasMatrixData.value
    ? `共 ${labeledEventCount.value} 条已标注事件，正确阻断 ${matrix.value.tp}，误报 ${matrix.value.fp}，正确放行 ${matrix.value.tn}，漏报 ${matrix.value.fn}`
    : "当前窗口暂无足够的恶意标注数据",
);

function percent(value: number | null): string {
  return value === null ? "--" : `${(value * 100).toFixed(1)}%`;
}

function pointDelta(before: number | null, after: number | null): string {
  if (before === null || after === null) return "--";
  return `${((before - after) * 100).toFixed(1)}pp`;
}

function barWidth(value: number | null): string {
  return value === null ? "0%" : `${Math.max(2, Math.min(100, value * 100))}%`;
}

function formatMaybeTime(value: string | null): string {
  return value ? formatDashboardDateTime(value) : "未提供";
}

function handleClearCaseLocator() {
  void router.replace({ path: "/evaluation" });
}

watch(
  [selectedCaseId, () => store.evaluation.cases.length],
  async ([caseId]) => {
    if (!caseId) return;
    await nextTick();
    document
      .querySelector(`[data-case-id="${CSS.escape(caseId)}"]`)
      ?.scrollIntoView({ block: "center", behavior: "smooth" });
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
  color: var(--color-success);
  text-align: right;
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
  color: var(--color-active);
  font-size: var(--font-size-24);
  letter-spacing: -0.025em;
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
  color: var(--color-success);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
}
.attack-asr__bars {
  display: grid;
  gap: 0.35rem;
}
.attack-asr__bars i {
  display: block;
  height: 0.45rem;
  min-width: 2px;
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
  min-height: 2rem;
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
</style>
