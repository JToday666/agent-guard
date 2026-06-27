<template>
  <div class="investigation-detail" :class="{ 'investigation-detail--evidence': Boolean(selectedEvent) }">
    <main class="workspace-panel investigation-detail__main" aria-labelledby="trace-title">
      <header class="page-header">
        <div>
          <p>事件溯源</p>
          <h1 id="trace-title">证据链</h1>
        </div>
        <RouterLink class="page-action" to="/investigations">返回事件调查</RouterLink>
      </header>
      <section v-if="traceDetailError && traceEvents.length" class="trace-detail-alert" role="status">
        <strong>Trace 详情加载失败</strong><p>{{ traceDetailError }}，当前显示已加载事件窗口中的证据。</p>
      </section>
      <ErrorState v-if="traceDetailError && !traceEvents.length" :is-retrying="isTraceLoading" :message="traceDetailError" @retry="handleTraceRetry" />
      <ErrorState v-else-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="store.refresh" />
      <LoadingState v-else-if="(store.status === 'loading' && !store.events.length) || (isTraceLoading && !traceEvents.length)" />
      <template v-else-if="trace">
        <MetricStrip :items="summaryItems" />
        <div class="trace-body section-divider">
          <section class="trace-provenance" aria-labelledby="provenance-title">
            <header>
              <div><h2 id="provenance-title">溯源图</h2><p>节点关系与因果链，点击节点查看详情</p></div>
            </header>
            <ProvenanceGraph v-if="provenance" :graph="provenance" :selected-node-id="selectedProvenanceNodeId" @select-node="handleSelectProvenanceNode" />
            <p v-else-if="provenanceError" class="provenance-error">溯源图加载失败：{{ provenanceError }}</p>
            <p v-else class="provenance-placeholder">溯源图加载中…</p>
          </section>
          <div class="trace-layout">
            <section class="trace-events" aria-labelledby="trace-events-title">
              <header><div><h2 id="trace-events-title">审计事件链路</h2><p>按发生顺序还原 Agent 行为与安全决策</p></div><span>{{ traceEvents.length }} 个节点</span></header>
              <TraceTimeline :events="traceEvents" :selected-event-id="selectedEventId" :trace-id="traceId" @select-event="handleTimelineSelectEvent" />
            </section>
            <aside class="trace-context" aria-label="Trace 上下文">
              <h2>调查上下文</h2>
              <dl>
                <div><dt>Trace ID</dt><dd><code>{{ traceId }}</code></dd></div>
                <div><dt>Case</dt><dd>{{ trace.caseId }}</dd></div>
                <div><dt>最终状态</dt><dd><StatusBadge :label="getTraceStatusLabel(trace.status)" :tone="getTraceStatusTone(trace.status)" /></dd></div>
                <div><dt>最后事件</dt><dd>{{ formatDashboardDateTime(trace.lastEventAt) }}</dd></div>
              </dl>
              <template v-if="selectedProvenanceNode">
                <div class="prov-node-detail">
                  <h3>节点详情</h3>
                  <dl class="prov-node-detail__dl">
                    <div><dt>类型</dt><dd>{{ selectedProvenanceNode.kind }}</dd></div>
                    <div><dt>标签</dt><dd>{{ selectedProvenanceNode.label }}</dd></div>
                    <div><dt>时间</dt><dd>{{ formatDashboardDateTime(selectedProvenanceNode.timestamp) }}</dd></div>
                  </dl>
                </div>
              </template>
              <RouterLink v-if="trace.approvalId" class="page-action trace-context__action" :to="`/approvals/${trace.approvalId}`">查看关联审批</RouterLink>
              <RouterLink v-if="trace.caseId !== '未提供'" class="page-action trace-context__action" :to="{ path: '/evaluation', query: { case_id: trace.caseId } }">查看评测样本</RouterLink>
            </aside>
          </div>
        </div>
      </template>
      <EmptyState v-else title="未找到证据链" message="该 Trace 不存在，或已经离开当前数据窗口。"><RouterLink to="/investigations">返回事件调查</RouterLink></EmptyState>
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
import ProvenanceGraph from "../components/ProvenanceGraph.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/States/ErrorState.vue";
import LoadingState from "../components/States/LoadingState.vue";
import TraceTimeline from "../components/TraceTimeline.vue";
import { buildInvestigationIndex, resolveInvestigationEvent } from "../data/investigation-index";
import { useDashboardStore } from "../stores/dashboardStore";
import type { ProvenanceNode, TraceSummary } from "../types/dashboard";
import { formatDashboardDateTime, getTraceStatusLabel, getTraceStatusTone } from "../utils/dashboard-formatters";
import { mergeInvestigationQuery } from "../utils/investigation-query";

defineOptions({ name: "InvestigationDetailPage" });
const route = useRoute();
const router = useRouter();
const store = useDashboardStore();
const traceId = computed(() => String(route.params.trace_id ?? ""));
const traceDetail = computed(() => store.traceDetails[traceId.value]);
const traceDetailError = computed(() => store.traceDetailErrors[traceId.value] ?? "");
const isTraceLoading = computed(() => store.traceDetailLoadingId === traceId.value);
const traceEvents = computed(() => traceDetail.value?.events.length ? traceDetail.value.events : store.investigationIndex.byTrace.get(traceId.value) ?? []);
const detailIndex = computed(() => buildInvestigationIndex(traceEvents.value));
const trace = computed(() => buildTraceSummary(traceId.value, traceEvents.value) ?? store.traces.find((t) => t.id === traceId.value));
const selectedEventId = computed(() => typeof route.query.event_id === "string" ? route.query.event_id : "");
const eventResolution = computed(() => resolveInvestigationEvent(detailIndex.value, selectedEventId.value, traceId.value));
const selectedEvent = computed(() => eventResolution.value.status === "found" ? eventResolution.value.event : undefined);
const provenance = computed(() => store.provenanceByTrace[traceId.value]);
const provenanceError = computed(() => store.provenanceErrors[traceId.value] ?? "");
const selectedProvenanceNodeId = computed<string | undefined>(() => typeof route.query.prov_node === "string" ? route.query.prov_node : undefined);
const selectedProvenanceNode = computed<ProvenanceNode | undefined>(() => provenance.value?.nodes.find((n) => n.nodeId === selectedProvenanceNodeId.value));
function handleSelectProvenanceNode(nodeId: string) {
  void router.replace({ path: `/investigations/${traceId.value}`, query: mergeInvestigationQuery(route.query, { prov_node: nodeId }) });
}
const summaryItems = computed(() => [
  { detail: "关联评测样本", label: "Case", value: trace.value?.caseId ?? "--" },
  { detail: "按时间顺序", label: "事件节点", value: String(traceEvents.value.length) },
  { detail: "链路最高风险", label: "最高风险", tone: "danger" as const, value: String(Math.max(0, ...traceEvents.value.map((e) => e.riskScore))) },
  { detail: "最新证据时间", label: "最后更新", value: trace.value ? formatDashboardDateTime(trace.value.lastEventAt) : "--" },
]);
watch([selectedEventId, traceEvents], async ([eventId]) => {
  if (!eventId) return;
  await nextTick();
  document.querySelector<HTMLElement>(`[data-event-id="${CSS.escape(eventId)}"]`)?.scrollIntoView({ block: "center" });
}, { immediate: true });
watch(traceId, (value) => {
  if (value) { void store.loadTraceDetail(value); void store.loadTraceProvenance(value); }
}, { immediate: true });
function handleTimelineSelectEvent(eventId: string) {
  // 时间线事件点击→高亮溯源图：通过 ref_id 前缀 "event:" 匹配
  const matchNode = provenance.value?.nodes.find(
    (n) => n.refId === `event:${eventId}` || n.refId === eventId
  );
  if (matchNode) {
    void router.replace({
      path: `/investigations/${traceId.value}`,
      query: mergeInvestigationQuery(route.query, { prov_node: matchNode.nodeId }),
    });
  }
}
function handleCloseEvidence() {
  void router.replace({ path: `/investigations/${traceId.value}`, query: mergeInvestigationQuery(route.query, { event_id: undefined }) });
}
function handleTraceRetry() { void store.loadTraceDetail(traceId.value); }
function buildTraceSummary(id: string, events: TraceSummaryEvent[]): TraceSummary | undefined {
  if (!events.length) return undefined;
  const last = events.at(-1)!;
  const isDenied = events.some((e) => e.decision === "deny");
  const isPaused = !isDenied && events.some((e) => e.decision === "ask");
  return { id, lastEventAt: last.occurredAt, caseId: last.caseId ?? "未提供", title: last.reason, status: isDenied ? "blocked" : isPaused ? "paused" : "allowed", approvalId: last.approvalId };
}
type TraceSummaryEvent = { approvalId?: string; caseId: string | null; decision: "allow" | "deny" | "ask"; occurredAt: string; reason: string; };
</script>

<style scoped lang="scss">
.investigation-detail { display: grid; grid-template-columns: minmax(0, 1fr); }
.investigation-detail--evidence { grid-template-columns: minmax(0, 1fr) minmax(22rem, 26rem); }
.investigation-detail__main { min-width: 0; }
.trace-body { display: grid; gap: var(--space-7); }
.trace-provenance { display: grid; gap: var(--space-4); }
.trace-provenance > header { align-items: start; display: flex; gap: var(--space-4); justify-content: space-between; flex-wrap: wrap; }
.trace-provenance h2, .trace-provenance p { margin: 0; }
.trace-provenance > header > div > p { color: var(--color-text-subtle); font-size: var(--font-size-12); margin-top: var(--space-1); }
.provenance-error { color: var(--color-danger); font-size: var(--font-size-13); margin: 0; padding: var(--space-3) 0; }
.provenance-placeholder { color: var(--color-text-subtle); font-size: var(--font-size-13); margin: 0; padding: var(--space-5) 0; text-align: center; }
.trace-layout { border-top: 1px solid var(--color-border); display: grid; gap: clamp(var(--space-5), 3vw, var(--space-7)); grid-template-columns: minmax(0, 1fr) 18rem; padding-top: var(--space-5); }
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
.trace-context__action { justify-self: start; }
.prov-node-detail { border-top: 1px solid var(--color-border); display: grid; gap: var(--space-3); padding-top: var(--space-3); }
.prov-node-detail h3 { font-size: var(--font-size-13); margin: 0; }
.prov-node-detail__dl { display: grid; gap: var(--space-2); margin: 0; }
.prov-node-detail__dl > div { display: grid; gap: var(--space-1); }
.prov-node-detail__dl dt { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.prov-node-detail__dl dd { font-size: var(--font-size-13); margin: 0; overflow-wrap: anywhere; }
.trace-detail-alert { background: var(--color-warning-soft); border-left: 3px solid var(--color-warning); display: grid; gap: var(--space-1); margin-bottom: var(--space-4); padding: var(--space-3); }
.trace-detail-alert p { color: var(--color-text-muted); margin: 0; }
@media (max-width: 1100px) { .investigation-detail, .investigation-detail--evidence { grid-template-columns: 1fr; } .trace-layout { grid-template-columns: 1fr; } .trace-context { border-left: 0; border-top: 1px solid var(--color-border); padding: var(--space-5) 0 0; position: static; } }
</style>
