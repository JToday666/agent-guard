<template>
  <section class="pre-enable-report" aria-labelledby="pre-enable-report-title">
    <header class="pre-enable-report__header">
      <div>
        <span>C10 · PRE-ENABLE OBSERVATION</span>
        <h2 id="pre-enable-report-title">正式决策与 V2 Shadow 预启用报告</h2>
        <p>功能证据与效果指标来自同一次 EvaluationRun；所有比率保留原始分子与分母。</p>
      </div>
      <StatusBadge :label="availabilityLabel" :tone="availabilityTone" />
    </header>

    <InlineNotice
      v-if="report.availability === 'unavailable'"
      title="C10 报告不可用"
      tone="warning"
    >
      <p>当前 EvaluationRun 未携带可验证的 typed C10 报告，不从样本表或近期审计窗口推算。</p>
    </InlineNotice>
    <template v-else>
      <InlineNotice
        v-if="report.availability === 'partial'"
        title="C10 报告部分可用"
        tone="warning"
      >
        <p>{{ report.missingReasons.join(" · ") }}</p>
      </InlineNotice>

      <div class="pre-enable-report__rails" aria-label="决策轨道">
        <article>
          <span>CURRENT OFFICIAL</span>
          <strong>正式决策继续生效</strong>
          <p>报告只读取 current official，不以 V2 结果替换运行时决策。</p>
        </article>
        <article class="is-shadow">
          <span>V2 SHADOW</span>
          <strong>影子观测</strong>
          <p>记录分叉、解释覆盖与 benign ASK，不改变 official 响应。</p>
        </article>
        <article class="is-gate">
          <span>FORMAL GATE B</span>
          <strong>未声明通过</strong>
          <p>效果仅作 observational 展示，不应用数值门槛。</p>
        </article>
      </div>

      <dl class="pre-enable-report__metrics" aria-label="C10 报告指标">
        <div v-for="metric in metrics" :key="metric.label">
          <dt>{{ metric.label }}</dt>
          <dd>{{ ratioValue(metric.value) }}</dd>
          <small>{{ ratioCounts(metric.value) }} · {{ metric.detail }}</small>
        </div>
      </dl>

      <div class="pre-enable-report__details">
        <section aria-labelledby="pre-enable-receipt-title">
          <header>
            <h3 id="pre-enable-receipt-title">Receipt population</h3>
            <StatusBadge
              :label="functionalEvidenceLabel"
              :tone="report.functionalEvidenceStatus === 'passed' ? 'success' : 'warning'"
            />
          </header>
          <dl>
            <div>
              <dt>Runtime profile</dt>
              <dd>{{ report.receiptEligibility?.runtimeProfile ?? "不可用" }}</dd>
            </div>
            <div>
              <dt>Eligibility revision</dt>
              <dd>{{ report.receiptEligibility?.eligibilityRevision ?? "不可用" }}</dd>
            </div>
            <div>
              <dt>Eligible actions</dt>
              <dd>{{ report.eligibleActionCount ?? "不可用" }}</dd>
            </div>
            <div>
              <dt>Terminal receipts</dt>
              <dd>{{ report.terminalReceiptCount ?? "不可用" }}</dd>
            </div>
            <div class="is-wide">
              <dt>Eligibility digest</dt>
              <dd>
                <code translate="no">{{
                  report.receiptEligibility?.eligibilityDigest ?? "不可用"
                }}</code>
              </dd>
            </div>
          </dl>
        </section>

        <section aria-labelledby="pre-enable-divergence-title">
          <header>
            <h3 id="pre-enable-divergence-title">Divergence explanation</h3>
            <span>{{ report.degradedDivergenceCount ?? "--" }} degraded</span>
          </header>
          <ul v-if="report.divergenceCategories.length" class="pre-enable-report__categories">
            <li v-for="item in report.divergenceCategories" :key="item.category">
              <code translate="no">{{ item.category }}</code
              ><strong>{{ item.count }}</strong>
            </li>
          </ul>
          <p v-else>未记录可展示的受控分叉类目。</p>
          <small>未解释分叉 {{ report.unexplainedDivergenceCount ?? "--" }}</small>
        </section>

        <section aria-labelledby="pre-enable-latency-title">
          <header><h3 id="pre-enable-latency-title">Latency observation</h3></header>
          <dl v-if="report.latency">
            <div>
              <dt>Average</dt>
              <dd>{{ milliseconds(report.latency.averageMs) }}</dd>
            </div>
            <div>
              <dt>P50</dt>
              <dd>{{ milliseconds(report.latency.p50Ms) }}</dd>
            </div>
            <div>
              <dt>P95</dt>
              <dd>{{ milliseconds(report.latency.p95Ms) }}</dd>
            </div>
            <div>
              <dt>P99</dt>
              <dd>{{ milliseconds(report.latency.p99Ms) }}</dd>
            </div>
            <div>
              <dt>Max</dt>
              <dd>{{ milliseconds(report.latency.maxMs) }}</dd>
            </div>
            <div>
              <dt>Method</dt>
              <dd>{{ report.latency.method }}</dd>
            </div>
          </dl>
          <p v-else>延迟投影不可用。</p>
        </section>

        <section aria-labelledby="pre-enable-functional-title">
          <header><h3 id="pre-enable-functional-title">功能与回滚证据</h3></header>
          <div class="pre-enable-report__checks">
            <article>
              <strong>Failure injection</strong>
              <ul>
                <li v-for="check in report.failureInjection" :key="check.checkId">
                  <StatusBadge
                    :label="check.status"
                    :tone="check.status === 'passed' ? 'success' : 'danger'"
                  />
                  <span
                    ><code translate="no">{{ check.checkId }}</code
                    >{{ check.reasonCode }} · {{ check.evidenceRefCount }} refs</span
                  >
                </li>
              </ul>
              <p v-if="!report.failureInjection.length">不可用</p>
            </article>
            <article>
              <strong>Flag rollback</strong>
              <ul>
                <li v-for="check in report.flagRollback" :key="check.checkId">
                  <StatusBadge
                    :label="check.status"
                    :tone="check.status === 'passed' ? 'success' : 'danger'"
                  />
                  <span
                    ><code translate="no">{{ check.checkId }}</code
                    >{{ check.reasonCode }} · {{ check.evidenceRefCount }} refs</span
                  >
                </li>
              </ul>
              <p v-if="!report.flagRollback.length">不可用</p>
            </article>
          </div>
        </section>
      </div>

      <footer class="pre-enable-report__footer">
        <span>Effect mode: observational</span>
        <span>Numerical thresholds: not applied</span>
        <span>Final ASR availability: {{ report.finalAsrAvailability ?? "unavailable" }}</span>
        <span
          >Decision label availability:
          {{ report.decisionLabelAvailability ?? "unavailable" }}</span
        >
      </footer>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";

import type { PreEnableRatioMetric, PreEnableReportPresentation } from "../../types/dashboard.ts";
import InlineNotice from "../common/InlineNotice.vue";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({ name: "PreEnableReportPanel" });

const props = defineProps<{ report: PreEnableReportPresentation }>();

const availabilityLabel = computed(() => {
  if (props.report.availability === "recorded") return "报告已记录";
  if (props.report.availability === "partial") return "报告部分可用";
  return "报告不可用";
});
const availabilityTone = computed<"neutral" | "success" | "warning">(() => {
  if (props.report.availability === "recorded") return "success";
  if (props.report.availability === "partial") return "warning";
  return "neutral";
});
const functionalEvidenceLabel = computed(() => {
  if (props.report.functionalEvidenceStatus === "passed") return "功能证据通过";
  if (props.report.functionalEvidenceStatus === "failed") return "功能证据失败";
  return "功能证据不可用";
});
const metrics = computed(() => [
  { label: "Receipt coverage", value: props.report.receiptCoverage, detail: "terminal / eligible" },
  { label: "Link conflicts", value: props.report.linkConflicts, detail: "conflict / eligible" },
  {
    label: "Official ↔ V2 divergence",
    value: props.report.officialV2Divergence,
    detail: "divergent / compared",
  },
  {
    label: "Explanation coverage",
    value: props.report.divergenceExplanationCoverage,
    detail: "categorized / divergent",
  },
  { label: "Benign ASK", value: props.report.benignAsk, detail: "shadow ASK / benign labeled" },
  {
    label: "Decision label coverage",
    value: props.report.decisionLabelCoverage,
    detail: "labeled / compared",
  },
  { label: "Final ASR", value: props.report.finalAsr, detail: "harmful / known outcomes" },
  {
    label: "Attack outcome coverage",
    value: props.report.attackOutcomeCoverage,
    detail: "known / attempts",
  },
  {
    label: "Latency sample coverage",
    value: props.report.latency?.sampleCoverage ?? null,
    detail: "sampled / eligible",
  },
]);

function ratioValue(metric: PreEnableRatioMetric | null): string {
  return metric?.value === null || metric === null ? "--" : `${(metric.value * 100).toFixed(1)}%`;
}

function ratioCounts(metric: PreEnableRatioMetric | null): string {
  return metric ? `${metric.numerator}/${metric.denominator}` : "--/--";
}

function milliseconds(value: number | null): string {
  return value === null ? "--" : `${value.toFixed(1)} ms`;
}
</script>

<style scoped lang="scss">
.pre-enable-report {
  border-block: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-5);
  padding-block: var(--space-5);
}

.pre-enable-report__header {
  align-items: start;
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
}

.pre-enable-report__header > div {
  display: grid;
  gap: var(--space-1);
}

.pre-enable-report__header span,
.pre-enable-report__footer,
.pre-enable-report__details header > span {
  color: var(--color-text-subtle);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
}

.pre-enable-report__header h2,
.pre-enable-report__header p,
.pre-enable-report__details h3,
.pre-enable-report__details p {
  margin: 0;
}

.pre-enable-report__header h2 {
  font-size: var(--font-size-18);
}

.pre-enable-report__header p,
.pre-enable-report__details p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}

.pre-enable-report__rails {
  display: grid;
  gap: var(--space-3);
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.pre-enable-report__rails article {
  border: 1px solid var(--color-border);
  border-left: 3px solid var(--color-active);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-2);
  padding: var(--space-3);
}

.pre-enable-report__rails article.is-shadow {
  border-left-color: var(--color-warning);
}

.pre-enable-report__rails article.is-gate {
  border-left-color: var(--color-text-subtle);
}

.pre-enable-report__rails span {
  color: var(--color-text-subtle);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
}

.pre-enable-report__rails strong {
  font-size: var(--font-size-14);
}

.pre-enable-report__rails p {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  line-height: 1.55;
  margin: 0;
}

.pre-enable-report__metrics {
  display: grid;
  gap: 1px;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin: 0;
  overflow: hidden;
}

.pre-enable-report__metrics > div {
  background: var(--color-surface-muted);
  display: grid;
  gap: var(--space-1);
  min-width: 0;
  padding: var(--space-3);
}

.pre-enable-report__metrics dt,
.pre-enable-report__details dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.pre-enable-report__metrics dd {
  font-size: var(--font-size-20);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-bold);
  margin: 0;
}

.pre-enable-report__metrics small,
.pre-enable-report__details small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.pre-enable-report__details {
  display: grid;
  gap: var(--space-3);
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.pre-enable-report__details > section {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-3);
  min-width: 0;
  padding: var(--space-3);
}

.pre-enable-report__details header {
  align-items: center;
  display: flex;
  gap: var(--space-3);
  justify-content: space-between;
}

.pre-enable-report__details h3 {
  font-size: var(--font-size-14);
}

.pre-enable-report__details dl {
  display: grid;
  gap: var(--space-2);
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
}

.pre-enable-report__details dl > div {
  min-width: 0;
}

.pre-enable-report__details dl > .is-wide {
  grid-column: 1 / -1;
}

.pre-enable-report__details dd {
  font-size: var(--font-size-12);
  margin: var(--space-1) 0 0;
  overflow-wrap: anywhere;
}

.pre-enable-report__categories,
.pre-enable-report__checks ul {
  display: grid;
  gap: var(--space-2);
  list-style: none;
  margin: 0;
  padding: 0;
}

.pre-enable-report__categories li {
  align-items: center;
  background: var(--color-surface-muted);
  display: flex;
  gap: var(--space-2);
  justify-content: space-between;
  padding: var(--space-2);
}

.pre-enable-report__categories code {
  font-size: var(--font-size-11);
  overflow-wrap: anywhere;
}

.pre-enable-report__checks {
  display: grid;
  gap: var(--space-3);
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.pre-enable-report__checks article {
  display: grid;
  gap: var(--space-2);
  min-width: 0;
}

.pre-enable-report__checks article > strong {
  font-size: var(--font-size-12);
}

.pre-enable-report__checks li {
  align-items: start;
  display: grid;
  gap: var(--space-2);
}

.pre-enable-report__checks li > span {
  color: var(--color-text-muted);
  display: grid;
  font-size: var(--font-size-11);
  overflow-wrap: anywhere;
}

.pre-enable-report__footer {
  border-top: 1px solid var(--color-border);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  padding-top: var(--space-3);
}

@media (max-width: 62rem) {
  .pre-enable-report__rails,
  .pre-enable-report__metrics,
  .pre-enable-report__details {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 38rem) {
  .pre-enable-report__header {
    align-items: stretch;
    flex-direction: column;
  }

  .pre-enable-report__checks,
  .pre-enable-report__details dl {
    grid-template-columns: 1fr;
  }

  .pre-enable-report__details dl > .is-wide {
    grid-column: auto;
  }
}
</style>
