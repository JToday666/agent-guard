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
      <section v-if="store.evaluationError" class="evaluation-alert" role="status">
        <strong>评测结果暂未更新</strong>
        <span>{{ store.evaluationError }}</span>
      </section>

      <section v-if="hasRunData" class="evaluation-run" aria-labelledby="run-title">
        <header>
          <div>
            <h2 id="run-title">最新评估</h2>
            <p>{{ store.evaluation.datasetLabel }}</p>
          </div>
          <dl>
            <div>
              <dt>运行 ID</dt>
              <dd>
                <code>{{ store.evaluation.runId }}</code>
              </dd>
            </div>
            <div>
              <dt>运行时间</dt>
              <dd>{{ formatMaybeTime(store.evaluation.runAt) }}</dd>
            </div>
            <div>
              <dt>展示样本</dt>
              <dd>{{ store.evaluation.cases.length }}</dd>
            </div>
          </dl>
        </header>

        <div class="asr-stage">
          <div class="asr-score asr-score--before">
            <span>防护前 ASR</span>
            <strong>{{ percent(store.evaluation.asrBefore) }}</strong>
          </div>
          <div class="asr-change">
            <span>ASR 降幅</span>
            <strong>{{ pointDelta(store.evaluation.asrBefore, store.evaluation.asrAfter) }}</strong>
          </div>
          <div class="asr-score asr-score--after">
            <span>防护后 ASR</span>
            <strong>{{ percent(store.evaluation.asrAfter) }}</strong>
          </div>
        </div>

        <AsrComparisonChart :before="store.evaluation.asrBefore" :after="store.evaluation.asrAfter" />
      </section>
      <EmptyState
        v-else
        title="暂无评测结果"
        message="评测结果写入后将在这里展示最新攻击成功率、防护效果和样本结果。"
      />

      <MetricStrip :items="metricItems" />

      <section
        v-if="store.evaluation.perAttack.length"
        class="attack-asr section-divider"
        aria-labelledby="attack-asr-title"
      >
        <header>
          <div>
            <h2 id="attack-asr-title">攻击类型 ASR</h2>
            <p>按防护前攻击成功率排序，对比防护前后变化</p>
          </div>
        </header>
        <div class="attack-asr__rows" role="list">
          <article v-for="row in store.evaluation.perAttack" :key="row.attackType" role="listitem">
            <div class="attack-asr__label">
              <strong>{{ row.attackType }}</strong>
              <span>{{ pointDelta(row.asrBefore, row.asrAfter) }}</span>
            </div>
            <div class="attack-asr__bars" aria-hidden="true">
              <i class="before" :style="{ width: barWidth(row.asrBefore) }"></i>
              <i class="after" :style="{ width: barWidth(row.asrAfter) }"></i>
            </div>
            <div class="attack-asr__values">
              <span>{{ percent(row.asrBefore) }}</span>
              <span>{{ percent(row.asrAfter) }}</span>
            </div>
          </article>
        </div>
      </section>

      <section v-if="hasRuntimeComparison" class="eval-runtime section-divider" aria-labelledby="runtime-perf-title">
        <header>
          <div>
            <h2 id="runtime-perf-title">运行时延迟对比</h2>
            <p>比较多个运行时的平均判定耗时</p>
          </div>
        </header>
        <div class="runtime-bars">
          <div v-for="row in runtimeLatency" :key="row.runtime" class="runtime-bar-row">
            <span class="runtime-bar-label">{{ row.runtime }}</span>
            <span class="runtime-bar-track"><i :style="{ width: `${row.pct}%` }"></i></span>
            <span class="runtime-bar-val">{{ row.avg === null ? "—" : `${row.avg.toFixed(1)} ms` }}</span>
          </div>
        </div>
      </section>

      <section class="eval-matrix section-divider" aria-labelledby="matrix-title">
        <header>
          <div>
            <h2 id="matrix-title">混淆矩阵</h2>
            <p>由当前审计窗口的恶意标注与阻断结果派生</p>
          </div>
        </header>
        <ConfusionMatrix v-if="hasMatrixData" :tp="matrix.tp" :fp="matrix.fp" :tn="matrix.tn" :fn="matrix.fn" />
        <p v-else class="eval-matrix__empty">暂无足够标注数据（需要样本恶意标注）</p>
      </section>

      <section class="evaluation-cases section-divider" aria-labelledby="case-title">
        <header>
          <div>
            <h2 id="case-title">展示样本</h2>
            <p>最新评测中的展示样本可追溯到对应证据链</p>
          </div>
          <span>{{ store.evaluation.cases.length }} 个展示样本</span>
        </header>
        <div v-if="selectedCaseId" class="case-locator" :class="{ 'case-locator--missing': !selectedCaseExists }">
          <span>{{
            selectedCaseExists ? `当前定位样本：${selectedCaseId}` : `未找到定位样本：${selectedCaseId}`
          }}</span>
          <button type="button" @click="handleClearCaseLocator">清除定位</button>
        </div>
        <div v-if="store.evaluation.cases.length" class="case-table-wrap">
          <table class="case-table">
            <caption>
              展示样本结果
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
        <EmptyState v-else title="暂无展示样本" message="最新评测包含样本明细后将在此展示。" />
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import AsrComparisonChart from "../components/charts/AsrComparisonChart.vue";
import ConfusionMatrix from "../components/charts/ConfusionMatrix.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import MetricStrip from "../components/common/MetricStrip.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import { formatDashboardDateTime, getDecisionLabel, getDecisionTone } from "../utils/dashboard-formatters";

defineOptions({ name: "EvaluationPage" });

const store = useDashboardStore();
const route = useRoute();
const router = useRouter();
const selectedCaseId = computed(() => (typeof route.query.case_id === "string" ? route.query.case_id : ""));
const selectedCaseExists = computed(() =>
  Boolean(selectedCaseId.value && store.evaluation.cases.some((row) => row.caseId === selectedCaseId.value)),
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
const hasMatrixData = computed(() => matrix.value.tp + matrix.value.fp + matrix.value.tn + matrix.value.fn > 0);
const metricItems = computed(() => [
  {
    detail: "当前审计窗口",
    label: "阻断率",
    route: "/investigations?blocked=true",
    tone: "success" as const,
    value: percent(store.evaluation.blockRate),
  },
  { detail: "当前审计窗口", label: "误报率 FPR", route: "/investigations", value: percent(store.evaluation.fpr) },
  {
    detail: "当前审计窗口",
    label: "漏报率 FNR",
    route: "/investigations?decision=allow",
    value: percent(store.evaluation.fnr),
  },
  {
    detail: "当前审计窗口",
    label: "平均判定延迟",
    route: "/system",
    value: store.evaluation.averageLatencyMs === null ? "--" : `${store.evaluation.averageLatencyMs.toFixed(1)} ms`,
  },
  { detail: "最新评测", label: "展示样本数", route: "/evaluation", value: String(store.evaluation.cases.length) },
]);
const runtimeLatency = computed(() => {
  const runtimes = ["langgraph", "openclaw"] as const;
  const rows = runtimes.map((runtime) => {
    const values = store.events
      .filter((event) => event.runtime === runtime && event.latencyMs != null)
      .map((event) => event.latencyMs as number);
    const avg = values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
    return { runtime, avg };
  });
  const max = Math.max(1, ...rows.map((row) => row.avg ?? 0));
  return rows.map((row) => ({ ...row, pct: row.avg ? (row.avg / max) * 100 : 0 }));
});
const hasRuntimeComparison = computed(() => runtimeLatency.value.filter((row) => row.avg !== null).length > 1);

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
.evaluation-alert {
  align-items: center;
  background: var(--color-warning-soft);
  border-left: 3px solid var(--color-warning);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  padding: var(--space-3) var(--space-4);
}
.evaluation-alert span {
  color: var(--color-text-muted);
  font-size: var(--font-size-13);
}
.evaluation-run {
  border-block: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-5);
  padding: var(--space-5) 0;
}
.evaluation-run > header {
  align-items: start;
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(0, 1fr) minmax(min(100%, 34rem), 1.15fr);
}
.evaluation-run h2,
.evaluation-run p {
  margin: 0;
}
.evaluation-run h2 {
  font-size: var(--font-size-20);
}
.evaluation-run p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
  margin-top: var(--space-1);
}
.evaluation-run dl {
  display: grid;
  gap: 1px;
  grid-template-columns: 1.2fr 1fr 0.55fr;
  margin: 0;
  overflow: hidden;
}
.evaluation-run dl > div {
  background: var(--color-surface-muted);
  min-width: 0;
  padding: var(--space-3);
}
.evaluation-run dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.evaluation-run dd {
  font-size: var(--font-size-13);
  margin: var(--space-1) 0 0;
  overflow-wrap: anywhere;
}
.asr-stage {
  align-items: stretch;
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
}
.asr-score,
.asr-change {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-2);
  min-width: 0;
  padding: var(--space-4);
}
.asr-score span,
.asr-change span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.asr-score strong {
  font-size: clamp(2rem, 5vw, 4rem);
  line-height: 0.95;
  overflow-wrap: anywhere;
}
.asr-score--before strong {
  color: var(--color-danger);
}
.asr-score--after strong {
  color: var(--color-success);
}
.asr-change {
  align-content: center;
  min-width: 8rem;
  text-align: center;
}
.asr-change strong {
  color: var(--color-active);
  font-size: var(--font-size-24);
}
.attack-asr,
.eval-runtime,
.eval-matrix,
.evaluation-cases {
  display: grid;
  gap: var(--space-4);
}
.attack-asr > header,
.eval-runtime > header,
.eval-matrix > header,
.evaluation-cases > header {
  align-items: start;
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
}
.attack-asr h2,
.attack-asr p,
.eval-runtime h2,
.eval-runtime p,
.eval-matrix h2,
.eval-matrix p,
.evaluation-cases h2,
.evaluation-cases p {
  margin: 0;
}
.attack-asr p,
.eval-runtime p,
.eval-matrix p,
.evaluation-cases p,
.evaluation-cases > header > span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin-top: var(--space-1);
}
.attack-asr__rows {
  display: grid;
  gap: var(--space-2);
}
.attack-asr__rows article {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(9rem, 1fr) minmax(10rem, 2fr) 6rem;
  padding: var(--space-3);
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
  border-radius: var(--radius-pill);
  display: block;
  height: 0.55rem;
  min-width: 2px;
}
.attack-asr__bars .before {
  background: var(--color-danger);
  opacity: 0.72;
}
.attack-asr__bars .after {
  background: var(--color-success);
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
  grid-template-columns: 6rem 1fr 5rem;
}
.runtime-bar-label {
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
}
.runtime-bar-track {
  background: var(--color-surface-muted);
  border-radius: 3px;
  height: 0.5rem;
  overflow: hidden;
}
.runtime-bar-track i {
  background: linear-gradient(90deg, var(--color-active), #7aa7ff);
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
.eval-matrix__empty {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
  margin: 0;
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
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  letter-spacing: 0;
}
.case-table__selected {
  background: var(--color-active-soft);
  box-shadow: inset 2px 0 var(--color-active);
}
@media (max-width: 760px) {
  .evaluation-run > header,
  .asr-stage,
  .attack-asr__rows article {
    grid-template-columns: 1fr;
  }
  .evaluation-run dl {
    grid-template-columns: 1fr;
  }
  .asr-change {
    text-align: left;
  }
  .case-table {
    min-width: 42rem;
  }
}
</style>
