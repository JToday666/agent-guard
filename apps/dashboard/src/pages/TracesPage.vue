<template>
  <section class="traces-page workspace-panel" aria-labelledby="traces-title">
    <header class="page-header">
      <div>
        <p>监控</p>
        <h1 id="traces-title">链路</h1>
      </div>
      <StatusBadge label="部分数据" tone="neutral" />
    </header>

    <div class="traces-page__grid">
      <section class="content-section">
        <h2>链路列表</h2>
        <div class="trace-list">
          <RouterLink v-for="trace in filteredTraces" :key="trace.id" :to="`/traces/${trace.id}`">
            <strong>{{ trace.id }}</strong>
            <span>{{ trace.title }}</span>
            <small>{{ trace.caseId }}</small>
          </RouterLink>
        </div>
      </section>

      <section class="content-section">
        <h2>链路预览</h2>
        <article v-for="trace in filteredTraces" :key="trace.id" class="trace-chain">
          <header>
            <strong>{{ trace.title }}</strong>
            <StatusBadge :label="getTraceLabel(trace.status)" :tone="getTraceTone(trace.status)" />
          </header>
          <ol>
            <li v-for="node in trace.nodes" :key="node">{{ node }}</li>
          </ol>
          <div class="link-row">
            <RouterLink :to="`/events?event_id=${trace.eventId}`">审计事件</RouterLink>
            <RouterLink v-if="trace.approvalId" :to="`/approvals/${trace.approvalId}`">
              审批
            </RouterLink>
            <RouterLink :to="`/evaluation?case_id=${trace.caseId}`">样本</RouterLink>
          </div>
        </article>
      </section>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";

import StatusBadge from "../components/StatusBadge.vue";
import { traces } from "../mocks/dashboard-data";
import type { TraceSummary } from "../types/dashboard";

defineOptions({
  name: "TracesPage",
});

const route = useRoute();
const latestTraces = computed(() =>
  [...traces].sort((left, right) => Date.parse(right.lastEventAt) - Date.parse(left.lastEventAt)),
);

const filteredTraces = computed(() => {
  const eventType = typeof route.query.event_type === "string" ? route.query.event_type : "";
  if (!eventType) return latestTraces.value;
  return latestTraces.value.filter((trace) =>
    trace.nodes.join(" ").toLowerCase().includes(eventType.toLowerCase()),
  );
});

function getTraceTone(status: TraceSummary["status"]): "neutral" | "success" | "warning" | "danger" {
  if (status === "blocked") return "danger";
  if (status === "paused") return "warning";
  return "success";
}

function getTraceLabel(status: TraceSummary["status"]): string {
  if (status === "blocked") return "已阻断";
  if (status === "paused") return "已暂停";
  return "已放行";
}
</script>

<style scoped lang="scss">
.traces-page {
  display: grid;
  gap: var(--space-5);
}

.traces-page__grid {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(16rem, 22rem) minmax(0, 1fr);
}

.trace-list,
.trace-chain,
.trace-chain ol {
  display: grid;
  gap: var(--space-3);
}

.trace-list a {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  display: grid;
  gap: var(--space-1);
  min-height: 4.5rem;
  min-width: 0;
  padding: var(--space-3);
  text-decoration: none;

  span,
  small {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  small {
    color: var(--color-text-muted);
  }
}

.trace-chain {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-3);
  padding: var(--space-4);

  header,
  .link-row {
    align-items: center;
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    justify-content: space-between;
  }

  ol {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  li {
    background: var(--color-surface-muted);
    border-radius: var(--radius-2);
    padding: var(--space-2) var(--space-3);
  }
}

@media (max-width: 820px) {
  .traces-page__grid {
    grid-template-columns: 1fr;
  }
}
</style>
