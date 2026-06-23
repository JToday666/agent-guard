<template>
  <div class="investigation-detail" :class="{ 'investigation-detail--evidence': Boolean(selectedEvent) }">
    <main class="workspace-panel investigation-detail__main" aria-labelledby="trace-title">
      <header class="page-header">
        <div><p>调查证据链</p><h1 id="trace-title">{{ trace?.id ?? traceId }}</h1></div>
        <RouterLink class="page-action" to="/investigations">返回调查</RouterLink>
      </header>
      <ErrorState v-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="store.refresh" />
      <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
      <template v-else-if="trace">
        <MetricStrip :items="summaryItems" />
        <div class="trace-layout section-divider">
          <section class="trace-events" aria-labelledby="trace-events-title">
            <header><div><h2 id="trace-events-title">审计事件链路</h2><p>按发生顺序还原 Agent 行为与安全决策</p></div><span>{{ traceEvents.length }} 个节点</span></header>
            <TraceTimeline :events="traceEvents" :selected-event-id="selectedEventId" :trace-id="traceId" />
          </section>
          <aside class="trace-context" aria-label="Trace 上下文">
            <h2>调查上下文</h2>
            <dl><div><dt>Case</dt><dd>{{ trace.caseId }}</dd></div><div><dt>最终状态</dt><dd><StatusBadge :label="getTraceStatusLabel(trace.status)" :tone="getTraceStatusTone(trace.status)" /></dd></div><div><dt>最后事件</dt><dd>{{ formatDashboardDateTime(trace.lastEventAt) }}</dd></div></dl>
            <RouterLink v-if="trace.approvalId" :to="`/approvals/${trace.approvalId}`">查看关联审批</RouterLink>
            <RouterLink v-if="trace.caseId !== '未提供'" :to="{ path: '/evaluation', query: { case_id: trace.caseId } }">查看评测样本</RouterLink>
          </aside>
        </div>
      </template>
      <EmptyState v-else title="未找到调查链路" message="该 Trace 不存在，或已经离开当前数据窗口。"><RouterLink to="/investigations">返回调查列表</RouterLink></EmptyState>
    </main>
    <DetailDrawer :is-open="Boolean(selectedEventId)" eyebrow="节点证据" :title="selectedEvent?.tool ?? '事件未找到'" @close="handleCloseEvidence">
      <EventEvidence v-if="selectedEvent" :event="selectedEvent" />
      <EmptyState v-else title="未找到事件" message="该事件不存在、已离开当前数据窗口，或不属于当前 Trace。" />
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import DetailDrawer from "../components/DetailDrawer.vue";
import EmptyState from "../components/EmptyState.vue";
import EventEvidence from "../components/EventEvidence.vue";
import MetricStrip from "../components/MetricStrip.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/States/ErrorState.vue";
import LoadingState from "../components/States/LoadingState.vue";
import TraceTimeline from "../components/TraceTimeline.vue";
import { resolveInvestigationEvent } from "../data/investigation-index";
import { useDashboardStore } from "../stores/dashboardStore";
import { formatDashboardDateTime, getTraceStatusLabel, getTraceStatusTone } from "../utils/dashboard-formatters";
import { mergeInvestigationQuery } from "../utils/investigation-query";

defineOptions({ name: "InvestigationDetailPage" });
const route = useRoute();
const router = useRouter();
const store = useDashboardStore();
const traceId = computed(() => String(route.params.trace_id));
const trace = computed(() => store.traces.find((item) => item.id === traceId.value));
const traceEvents = computed(() => store.investigationIndex.byTrace.get(traceId.value) ?? []);
const selectedEventId = computed(() => typeof route.query.event_id === "string" ? route.query.event_id : "");
const eventResolution = computed(() => resolveInvestigationEvent(store.investigationIndex, selectedEventId.value, traceId.value));
const selectedEvent = computed(() => eventResolution.value.status === "found" ? eventResolution.value.event : undefined);
const summaryItems = computed(() => [
  { detail: "关联评测样本", label: "Case", value: trace.value?.caseId ?? "--" },
  { detail: "按时间顺序", label: "事件节点", value: String(traceEvents.value.length) },
  { detail: "链路最高风险", label: "最高风险", tone: "danger" as const, value: String(Math.max(0, ...traceEvents.value.map((event) => event.riskScore))) },
  { detail: "最新证据时间", label: "最后更新", value: trace.value ? formatDashboardDateTime(trace.value.lastEventAt) : "--" },
]);

watch([selectedEventId, traceEvents], async ([eventId]) => {
  if (!eventId) return;
  await nextTick();
  const eventElement = document.querySelector<HTMLElement>(`[data-event-id="${CSS.escape(eventId)}"]`);
  eventElement?.scrollIntoView({ block: "center" });
}, { immediate: true });

function handleCloseEvidence() {
  void router.replace({ path: `/investigations/${traceId.value}`, query: mergeInvestigationQuery(route.query, { event_id: undefined }) });
}
</script>

<style scoped lang="scss">
.investigation-detail { display: grid; grid-template-columns: minmax(0, 1fr); }
.investigation-detail--evidence { grid-template-columns: minmax(0, 1fr) minmax(22rem, 26rem); }
.investigation-detail__main { min-width: 0; }
.trace-layout { display: grid; gap: clamp(var(--space-5), 3vw, var(--space-7)); grid-template-columns: minmax(0, 1fr) 18rem; margin-top: var(--space-6); }
.trace-events { display: grid; gap: var(--space-5); }
.trace-events > header { align-items: start; display: flex; justify-content: space-between; }
.trace-events h2, .trace-events p { margin: 0; }
.trace-events p, .trace-events > header > span { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.trace-context { align-self: start; border-left: 1px solid var(--color-border); display: grid; gap: var(--space-4); padding-left: var(--space-5); position: sticky; top: calc(var(--top-bar-height) + var(--space-5)); }
.trace-context h2 { font-size: var(--font-size-16); margin: 0; }
.trace-context dl { display: grid; gap: var(--space-3); margin: 0; }
.trace-context dl > div { display: grid; gap: var(--space-1); }
.trace-context dt { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.trace-context dd { margin: 0; overflow-wrap: anywhere; }
.trace-context a { color: var(--color-link); font-size: var(--font-size-13); }
@media (max-width: 1100px) { .investigation-detail, .investigation-detail--evidence { grid-template-columns: 1fr; } .trace-layout { grid-template-columns: 1fr; } .trace-context { border-left: 0; border-top: 1px solid var(--color-border); padding: var(--space-5) 0 0; position: static; } }
</style>
