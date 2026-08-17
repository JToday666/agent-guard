<template>
  <section class="competition-report" aria-labelledby="competition-report-title">
    <header class="competition-report__header">
      <div>
        <span>LANGGRAPH · COMPETITION PROFILE</span>
        <h2 id="competition-report-title">Competition profile official</h2>
        <p>仅展示 competition-langgraph-v2 专项产物；不代表正式 C11、Gate B 或 S5-O。</p>
      </div>
      <StatusBadge :label="statusLabel" :tone="statusTone" />
    </header>

    <dl class="competition-report__summary">
      <div>
        <dt>Provider / Model</dt>
        <dd>{{ report.providerId ?? "未记录" }} / {{ report.model ?? "未记录" }}</dd>
      </div>
      <div>
        <dt>Case runs</dt>
        <dd>{{ report.attemptedCaseRuns }} / {{ report.expectedCaseRuns }}</dd>
      </div>
      <div>
        <dt>Invalid</dt>
        <dd>{{ report.invalidCaseRuns }}</dd>
      </div>
      <div>
        <dt>Qualification</dt>
        <dd>{{ report.competitionQualified ? "qualified" : "not qualified" }}</dd>
      </div>
    </dl>

    <div class="competition-report__table-wrap">
      <table>
        <thead>
          <tr>
            <th>Arm</th>
            <th>完整性</th>
            <th>ASR</th>
            <th>FPR</th>
            <th>Benign success</th>
            <th>V2 selected</th>
            <th>Legacy floor</th>
            <th>Receipt</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="arm in report.arms" :key="arm.armId">
            <th scope="row">{{ arm.armId }}</th>
            <td>{{ arm.evaluable }}/{{ arm.attempted }} · {{ arm.invalid }} invalid</td>
            <td>{{ percent(arm.asr) }}</td>
            <td>{{ percent(arm.fpr) }}</td>
            <td>{{ percent(arm.benignSuccess) }}</td>
            <td>{{ percent(arm.v21SelectionRate) }}</td>
            <td>{{ percent(arm.legacyFloorRate) }}</td>
            <td>{{ percent(arm.receiptCoverage) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";

import type { CompetitionReportPresentation } from "../../types/dashboard.ts";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({ name: "CompetitionReportPanel" });

const props = defineProps<{ report: CompetitionReportPresentation }>();

const statusLabel = computed(() => {
  if (props.report.status === "passed") return "完整性通过";
  if (props.report.status === "functional_contract_failed") return "契约失败";
  return "运行无效";
});
const statusTone = computed<"success" | "danger" | "warning">(() => {
  if (props.report.status === "passed" && props.report.competitionQualified) return "success";
  if (props.report.status === "functional_contract_failed") return "danger";
  return "warning";
});

function percent(value: number | null): string {
  return value === null ? "--" : `${(value * 100).toFixed(1)}%`;
}
</script>

<style scoped>
.competition-report {
  display: grid;
  gap: 1rem;
  margin-top: 1.25rem;
  padding: 1.25rem;
  border: 1px solid var(--color-border);
  border-radius: 1rem;
  background: var(--color-surface);
}

.competition-report__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
}

.competition-report__header span,
.competition-report__header p,
.competition-report dt {
  color: var(--color-text-muted);
}

.competition-report__header h2,
.competition-report__header p {
  margin: 0.25rem 0 0;
}

.competition-report__summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.75rem;
  margin: 0;
}

.competition-report__summary > div {
  padding: 0.75rem;
  border-radius: 0.75rem;
  background: var(--color-surface-muted);
}

.competition-report__summary dd {
  margin: 0.25rem 0 0;
  font-weight: 700;
}

.competition-report__table-wrap {
  overflow-x: auto;
}

.competition-report table {
  width: 100%;
  border-collapse: collapse;
  white-space: nowrap;
}

.competition-report th,
.competition-report td {
  padding: 0.65rem 0.75rem;
  border-bottom: 1px solid var(--color-border);
  text-align: left;
}

@media (max-width: 900px) {
  .competition-report__summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
