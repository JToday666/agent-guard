<template>
  <section class="overview-page workspace-panel" aria-labelledby="overview-title">
    <header class="page-header">
      <div>
        <p>监控</p>
        <h1 id="overview-title">总览</h1>
      </div>
      <RouterLink class="page-action" to="/events">查看事件</RouterLink>
    </header>

    <div class="metric-grid">
      <MetricCard
        v-for="metric in metricCards"
        :key="metric.label"
        :label="metric.label"
        :route="metric.route"
        :tone="metric.tone"
        :value="metric.value"
      />
    </div>

    <div class="overview-page__grid">
      <section class="content-section">
        <h2>决策趋势</h2>
        <div class="bar-list" aria-label="决策趋势">
          <RouterLink to="/events?decision=allow"><span style="width: 72%">放行</span></RouterLink>
          <RouterLink to="/events?decision=deny"><span style="width: 38%">拒绝</span></RouterLink>
          <RouterLink to="/events?decision=ask"><span style="width: 16%">待确认</span></RouterLink>
        </div>
      </section>

      <section class="content-section">
        <h2>严重性分布</h2>
        <div class="bar-list" aria-label="严重性分布">
          <RouterLink to="/events?severity=critical"><span style="width: 18%">严重</span></RouterLink>
          <RouterLink to="/events?severity=high"><span style="width: 34%">高</span></RouterLink>
          <RouterLink to="/events?severity=medium"><span style="width: 48%">中</span></RouterLink>
          <RouterLink to="/events?severity=low"><span style="width: 72%">低</span></RouterLink>
        </div>
      </section>
    </div>

    <section class="content-section">
      <h2>最新高风险事件</h2>
      <div class="compact-list">
        <RouterLink v-for="event in highRiskEvents" :key="event.id" :to="`/events?event_id=${event.id}`">
          <span>{{ event.time }}</span>
          <strong>{{ event.tool }}</strong>
          <small>{{ event.reason }}</small>
        </RouterLink>
      </div>
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";

import MetricCard from "../components/MetricCard.vue";
import { auditEvents, metricCards } from "../mocks/dashboard-data";

defineOptions({
  name: "OverviewPage",
});

const highRiskEvents = computed(() =>
  auditEvents.filter((event) => event.severity === "critical" || event.severity === "high"),
);
</script>

<style scoped lang="scss">
.overview-page {
  display: grid;
  gap: var(--space-6);
}

.metric-grid,
.overview-page__grid {
  display: grid;
  gap: var(--space-5);
}

.metric-grid {
  grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
}

.overview-page__grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.bar-list,
.compact-list {
  display: grid;
  gap: var(--space-3);
}

.bar-list a {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  min-height: 2rem;
  overflow: hidden;
  text-decoration: none;

  &:hover {
    border-color: var(--color-active-border);
    box-shadow: var(--shadow-subtle);
  }
}

.bar-list span {
  align-items: center;
  background: var(--color-active-soft);
  display: flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  min-height: 2rem;
  min-width: 5rem;
  padding: 0 var(--space-3);
}

.compact-list a {
  align-items: center;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 4rem 8rem minmax(0, 1fr);
  min-height: 3rem;
  padding: 0 var(--space-3);
  text-decoration: none;

  &:hover {
    background: var(--color-row-hover);
    border-color: var(--color-active-border);
  }

  small {
    color: var(--color-text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}

@media (max-width: 800px) {
  .overview-page__grid,
  .compact-list a {
    grid-template-columns: 1fr;
  }
}
</style>
