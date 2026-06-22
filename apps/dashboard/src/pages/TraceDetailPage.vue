<template>
  <section class="trace-detail workspace-panel" aria-labelledby="trace-detail-title">
    <header class="page-header">
      <div><p>证据链详情</p><h1 id="trace-detail-title">{{ trace?.id ?? traceId }}</h1></div>
      <RouterLink class="page-action" to="/traces">返回链路</RouterLink>
    </header>
    <template v-if="trace">
      <section class="trace-summary">
        <div><span>样本</span><strong>{{ trace.caseId }}</strong></div>
        <div><span>最终状态</span><StatusBadge :label="getTraceStatusLabel(trace.status)" :tone="getTraceStatusTone(trace.status)" /></div>
        <div><span>最后事件</span><strong>{{ formatDashboardDateTime(trace.lastEventAt) }}</strong></div>
      </section>
      <section class="timeline-section">
        <header><h2>审计事件链路</h2><p>按事件发生顺序展示关联证据</p></header>
        <ol class="timeline">
          <li v-for="(event, index) in traceEvents" :key="event.id" :class="`timeline--${event.decision}`">
            <span class="timeline__index">{{ index + 1 }}</span>
            <div class="timeline__content">
              <header><strong>{{ event.stage }}</strong><time>{{ event.time }}</time></header>
              <h3>{{ event.tool }} · {{ event.resource }}</h3>
              <p>{{ event.reason }}</p>
              <div class="timeline__meta"><StatusBadge :label="getDecisionLabel(event.decision)" :tone="getDecisionTone(event.decision)" /><span>风险 {{ event.riskScore }}</span><RouterLink :to="`/events?event_id=${event.id}`">事件证据</RouterLink></div>
            </div>
          </li>
        </ol>
      </section>
    </template>
    <EmptyState v-else title="未找到链路" message="当前链路不存在或暂无审计事件。" />
  </section>
</template>
<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
  getTraceStatusLabel,
  getTraceStatusTone,
} from "../utils/dashboard-formatters";
defineOptions({ name: "TraceDetailPage" });
const route = useRoute();
const store = useDashboardStore();
const traceId = computed(() => String(route.params.trace_id));
const trace = computed(() => store.traces.find((item) => item.id === traceId.value));
const traceEvents = computed(() => store.events.filter((event) => event.traceId === traceId.value).sort((a, b) => Date.parse(a.occurredAt) - Date.parse(b.occurredAt)));
</script>
<style scoped lang="scss">
.trace-detail { display: grid; gap: var(--space-5); }
.trace-summary { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); display: grid; grid-template-columns: repeat(3, 1fr); overflow: hidden; }
.trace-summary > div { border-right: 1px solid var(--color-border); display: grid; gap: var(--space-2); padding: var(--space-4); }
.trace-summary > div:last-child { border-right: 0; }
.trace-summary span { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.timeline-section { display: grid; gap: var(--space-5); max-width: 58rem; }
.timeline-section > header h2, .timeline-section > header p { margin: 0; }
.timeline-section > header p { color: var(--color-text-subtle); margin-top: var(--space-1); }
.timeline { display: grid; gap: 0; list-style: none; margin: 0; padding: 0; }
.timeline li { display: grid; gap: var(--space-4); grid-template-columns: 2.5rem minmax(0, 1fr); position: relative; }
.timeline li:not(:last-child)::before { background: var(--color-border); bottom: 0; content: ""; left: 1.2rem; position: absolute; top: 2.5rem; width: 2px; }
.timeline__index { align-items: center; background: var(--color-surface); border: 2px solid var(--color-active); border-radius: 50%; display: flex; font-weight: var(--font-weight-bold); height: 2.5rem; justify-content: center; position: relative; width: 2.5rem; z-index: 1; }
.timeline--deny .timeline__index { border-color: var(--color-danger); color: var(--color-danger); }
.timeline--ask .timeline__index { border-color: var(--color-warning); color: var(--color-warning); }
.timeline__content { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); display: grid; gap: var(--space-3); margin-bottom: var(--space-4); padding: var(--space-4); }
.timeline__content header, .timeline__meta { align-items: center; display: flex; flex-wrap: wrap; gap: var(--space-3); justify-content: space-between; }
.timeline__content time, .timeline__content p { color: var(--color-text-muted); }
.timeline__content h3, .timeline__content p { margin: 0; }
.timeline__content h3 { font-size: var(--font-size-16); overflow-wrap: anywhere; }
.timeline__meta { justify-content: flex-start; }
.timeline__meta a { margin-left: auto; }
@media (max-width: 640px) { .trace-summary { grid-template-columns: 1fr; } .trace-summary > div { border-bottom: 1px solid var(--color-border); border-right: 0; } }
</style>
