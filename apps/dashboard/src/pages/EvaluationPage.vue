<template>
  <section class="evaluation-page workspace-panel" aria-labelledby="evaluation-title">
    <header class="page-header">
      <div>
        <p>评测</p>
        <h1 id="evaluation-title">评测</h1>
      </div>
      <StatusBadge :label="caseLabel" tone="neutral" />
    </header>

    <div class="metric-grid">
      <MetricCard label="防护前 ASR" route="/evaluation" tone="danger" value="73.2%" />
      <MetricCard label="防护后 ASR" route="/evaluation" tone="success" value="4.8%" />
      <MetricCard label="阻断率" route="/events?blocked=true" tone="success" value="91.4%" />
      <MetricCard label="FPR" route="/evaluation?subset=benign" tone="neutral" value="1.6%" />
    </div>

    <section class="content-section">
      <h2>样本结果</h2>
      <div class="case-list">
        <article v-for="trace in traces" :key="trace.caseId" class="case-list__item">
          <strong>{{ trace.caseId }}</strong>
          <span>{{ trace.title }}</span>
          <RouterLink :to="`/traces/${trace.id}`">链路</RouterLink>
        </article>
      </div>
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";

import MetricCard from "../components/MetricCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { traces } from "../mocks/dashboard-data";

defineOptions({
  name: "EvaluationPage",
});

const route = useRoute();
const caseLabel = computed(() => {
  const caseId = route.query.case_id;
  return typeof caseId === "string" ? `样本 ${caseId}` : "AttackBench";
});
</script>

<style scoped lang="scss">
.evaluation-page {
  display: grid;
  gap: var(--space-5);
}

.metric-grid {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
}

.case-list {
  display: grid;
  gap: var(--space-3);
}

.case-list__item {
  align-items: center;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 8rem minmax(0, 1fr) auto;
  min-height: 3.25rem;
  padding: 0 var(--space-3);

  span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}

@media (max-width: 640px) {
  .case-list__item {
    align-items: start;
    grid-template-columns: 1fr;
    padding: var(--space-3);
  }
}
</style>
