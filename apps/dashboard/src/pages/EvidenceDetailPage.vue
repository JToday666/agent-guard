<template>
  <div class="evidence-detail">
    <section class="workspace-panel evidence-detail__main" aria-labelledby="trace-title">
      <header class="page-header">
        <div>
          <h1 id="trace-title">证据链</h1>
        </div>
        <div class="trace-header-actions">
          <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
          <RouterLink class="page-action" to="/investigations">返回事件调查</RouterLink>
        </div>
      </header>
      <InlineNotice
        v-if="traceDetailError && traceEvents.length"
        class="trace-detail-alert"
        title="证据刷新未完成"
        tone="warning"
      >
        <p>{{ traceDetailError }}。当前只展示已加载审计窗口内的匹配事件，链路可能不完整。</p>
        <button class="inline-retry" type="button" @click="handleTraceRetry">重新加载证据链</button>
      </InlineNotice>
      <ErrorState
        v-if="traceDetailError && !traceEvents.length"
        :is-retrying="isTraceLoading"
        :message="traceDetailError"
        @retry="handleTraceRetry"
      />
      <ErrorState
        v-else-if="store.status === 'error' && store.error"
        :is-retrying="store.isManualRefreshing"
        :message="store.error"
        @retry="store.refresh"
      />
      <LoadingState
        v-else-if="
          (store.status === 'loading' && !store.events.length) ||
          (isTraceLoading && !traceEvents.length)
        "
      />
      <template v-else-if="trace">
        <MetricStrip :items="summaryItems" />
        <section
          v-if="traceConclusion"
          class="trace-conclusion"
          aria-labelledby="trace-conclusion-title"
        >
          <header>
            <span>最终结论</span>
            <h2 id="trace-conclusion-title">{{ traceConclusion.title }}</h2>
          </header>
          <dl>
            <div>
              <dt>原因</dt>
              <dd>{{ traceConclusion.reason }}</dd>
            </div>
            <div>
              <dt>命中规则</dt>
              <dd>
                <template v-if="!traceConclusion.ruleHits.length"
                  ><span>未命中阻断规则</span></template
                >
                <template v-else
                  ><code v-for="rule in traceConclusion.ruleHits" :key="rule">{{
                    ruleLabel(rule)
                  }}</code></template
                >
              </dd>
            </div>
            <div>
              <dt>结果</dt>
              <dd>{{ traceConclusion.result }}</dd>
            </div>
          </dl>
        </section>
        <div class="trace-body section-divider">
          <div class="trace-layout">
            <section class="trace-events" aria-labelledby="trace-events-title">
              <header>
                <div>
                  <h2 id="trace-events-title">审计事件链路</h2>
                  <p>按发生顺序还原 Agent 行为与安全决策</p>
                </div>
                <span>{{ traceEvents.length }} 个节点</span>
              </header>
              <TraceTimeline
                :events="traceEvents"
                :selected-event-id="selectedEventId"
                :trace-id="traceId"
                @select-event="handleTimelineSelectEvent"
              />
            </section>
            <aside class="trace-context" aria-label="证据链上下文">
              <h2>调查上下文</h2>
              <dl>
                <div>
                  <dt>证据链 ID</dt>
                  <dd>
                    <code>{{ traceId }}</code>
                  </dd>
                </div>
                <div>
                  <dt>Case</dt>
                  <dd>{{ trace.caseId }}</dd>
                </div>
                <div>
                  <dt>最终状态</dt>
                  <dd>
                    <StatusBadge
                      :label="getTraceStatusLabel(trace.status)"
                      :tone="getTraceStatusTone(trace.status)"
                    />
                  </dd>
                </div>
                <div>
                  <dt>最后事件</dt>
                  <dd>{{ formatDashboardDateTime(trace.lastEventAt) }}</dd>
                </div>
              </dl>
              <template v-if="selectedProvenanceNode">
                <div class="prov-node-detail">
                  <h3>节点详情</h3>
                  <dl class="prov-node-detail__dl">
                    <div>
                      <dt>类型</dt>
                      <dd>{{ selectedProvenanceNode.kind }}</dd>
                    </div>
                    <div>
                      <dt>标签</dt>
                      <dd>{{ formatRuleIdsInTextForDisplay(selectedProvenanceNode.label) }}</dd>
                    </div>
                    <div>
                      <dt>时间</dt>
                      <dd>{{ formatDashboardDateTime(selectedProvenanceNode.timestamp) }}</dd>
                    </div>
                  </dl>
                </div>
              </template>
              <RouterLink
                v-if="trace.approvalId"
                class="page-action trace-context__action"
                :to="`/approvals/${trace.approvalId}`"
                >查看关联审批</RouterLink
              >
              <RouterLink
                v-if="trace.caseId !== '未提供'"
                class="page-action trace-context__action"
                :to="{ path: '/evaluation', query: { case_id: trace.caseId } }"
                >查看评测样本</RouterLink
              >
            </aside>
          </div>

          <section class="trace-provenance section-divider" aria-labelledby="provenance-title">
            <header>
              <div>
                <h2 id="provenance-title">溯源关系</h2>
                <p>以关系图补充时间线，点击节点可定位对应事件证据</p>
              </div>
            </header>
            <InlineNotice v-if="provenanceError" title="溯源关系刷新未完成" tone="warning">
              <p>{{ provenanceError }}</p>
              <button class="inline-retry" type="button" @click="handleProvenanceRetry">
                重新加载溯源关系
              </button>
            </InlineNotice>
            <ProvenanceGraph
              v-if="provenance"
              :graph="provenance"
              :selected-node-id="selectedProvenanceNodeId"
              @select-node="handleSelectProvenanceNode"
            />
            <p v-else-if="!provenanceError" class="provenance-placeholder">溯源关系加载中…</p>
          </section>
        </div>
      </template>
      <EmptyState v-else title="未找到证据链" message="该证据链不存在，或已经离开当前数据窗口。"
        ><RouterLink to="/investigations">返回事件调查</RouterLink></EmptyState
      >
    </section>
    <DetailDrawer
      :is-open="Boolean(selectedEventId)"
      eyebrow="节点证据"
      :title="selectedEvent?.tool ?? '事件未找到'"
      @close="handleCloseEvidence"
    >
      <EventEvidence v-if="selectedEvent" :event="selectedEvent" />
      <EmptyState
        v-else
        title="未找到事件"
        message="该事件不存在、已离开当前数据窗口，或不属于当前证据链。"
      />
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, nextTick, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import DataFreshness from "../components/common/DataFreshness.vue";
import DetailDrawer from "../components/common/DetailDrawer.vue";
import EmptyState from "../components/common/EmptyState.vue";
import EventEvidence from "../components/evidence/EventEvidence.vue";
import InlineNotice from "../components/common/InlineNotice.vue";
import MetricStrip from "../components/common/MetricStrip.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import TraceTimeline from "../components/evidence/TraceTimeline.vue";
import {
  buildInvestigationIndex,
  buildTraceConclusion,
  buildTraceSummary,
  resolveInvestigationEvent,
} from "../data/investigations";
import { useDashboardStore } from "../stores/dashboardStore";
import type { ProvenanceNode } from "../types/dashboard";
import {
  formatDashboardDateTime,
  getTraceStatusLabel,
  getTraceStatusTone,
} from "../utils/dashboard-formatters";
import { mergeInvestigationQuery } from "../utils/investigation-query";
import { findProvenanceNodeForEvent, resolveProvenanceEventId } from "../utils/provenance";
import { formatRuleIdsInTextForDisplay, ruleLabel } from "../utils/rule-display";

defineOptions({ name: "EvidenceDetailPage" });
const ProvenanceGraph = defineAsyncComponent(
  () => import("../components/evidence/ProvenanceGraph.vue"),
);
const route = useRoute();
const router = useRouter();
const store = useDashboardStore();
const traceId = computed(() => String(route.params.trace_id ?? ""));
const traceDetail = computed(() => store.traceDetails[traceId.value]);
const traceDetailError = computed(() => store.traceDetailErrors[traceId.value] ?? "");
const isTraceLoading = computed(() => store.traceDetailLoadingId === traceId.value);
const traceEvents = computed(() =>
  traceDetail.value?.events.length
    ? traceDetail.value.events
    : (store.investigationIndex.byTrace.get(traceId.value) ?? []),
);
const detailIndex = computed(() => buildInvestigationIndex(traceEvents.value));
const trace = computed(
  () =>
    buildTraceSummary(traceId.value, traceEvents.value) ??
    store.traces.find((t) => t.id === traceId.value),
);
const traceConclusion = computed(() => buildTraceConclusion(traceEvents.value));
const selectedEventId = computed(() =>
  typeof route.query.event_id === "string" ? route.query.event_id : "",
);
const eventResolution = computed(() =>
  resolveInvestigationEvent(detailIndex.value, selectedEventId.value, traceId.value),
);
const selectedEvent = computed(() =>
  eventResolution.value.status === "found" ? eventResolution.value.event : undefined,
);
const provenance = computed(() => store.provenanceByTrace[traceId.value]);
const provenanceError = computed(() => store.provenanceErrors[traceId.value] ?? "");
const selectedProvenanceNodeId = computed<string | undefined>(() =>
  typeof route.query.prov_node === "string" ? route.query.prov_node : undefined,
);
const selectedProvenanceNode = computed<ProvenanceNode | undefined>(() =>
  provenance.value?.nodes.find((n) => n.nodeId === selectedProvenanceNodeId.value),
);
function handleSelectProvenanceNode(nodeId: string) {
  const node = provenance.value?.nodes.find((item) => item.nodeId === nodeId);
  const eventId = resolveProvenanceEventId(node, traceEvents.value);
  void router.replace({
    path: `/evidence/${traceId.value}`,
    query: mergeInvestigationQuery(route.query, { prov_node: nodeId, event_id: eventId }),
  });
}
const summaryItems = computed(() => [
  { detail: "关联评测样本", label: "Case", value: trace.value?.caseId ?? "--" },
  { detail: "按时间顺序", label: "事件节点", value: String(traceEvents.value.length) },
  {
    detail: "链路最高风险",
    label: "最高风险",
    tone: "danger" as const,
    value: String(Math.max(0, ...traceEvents.value.map((e) => e.riskScore))),
  },
  {
    detail: "最新证据时间",
    label: "最后更新",
    value: trace.value ? formatDashboardDateTime(trace.value.lastEventAt) : "--",
  },
]);
watch(
  [selectedEventId, traceEvents],
  async ([eventId]) => {
    if (!eventId) return;
    await nextTick();
    document
      .querySelector<HTMLElement>(`[data-event-id="${CSS.escape(eventId)}"]`)
      ?.scrollIntoView({ block: "center" });
  },
  { immediate: true },
);
watch(
  traceId,
  (value) => {
    if (value) {
      void store.loadTraceDetail(value);
      void store.loadTraceProvenance(value);
    }
  },
  { immediate: true },
);
function handleTimelineSelectEvent(eventId: string) {
  const matchNode = findProvenanceNodeForEvent(provenance.value?.nodes ?? [], eventId);
  void router.replace({
    path: `/evidence/${traceId.value}`,
    query: mergeInvestigationQuery(route.query, {
      prov_node: matchNode?.nodeId,
      event_id: eventId,
    }),
  });
}
function handleCloseEvidence() {
  void router.replace({
    path: `/evidence/${traceId.value}`,
    query: mergeInvestigationQuery(route.query, { event_id: undefined }),
  });
}
function handleTraceRetry() {
  void store.loadTraceDetail(traceId.value, true);
}
function handleProvenanceRetry() {
  void store.loadTraceProvenance(traceId.value, true);
}
</script>

<style scoped lang="scss">
.evidence-detail {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  height: calc(100vh - var(--top-bar-height));
  overflow: hidden;
}
.evidence-detail__main {
  min-width: 0;
  overflow-y: auto;
  min-height: 0;
}
.trace-conclusion {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-left: 3px solid var(--color-active);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-4);
  padding: var(--space-4);
}
.trace-conclusion header {
  display: grid;
  gap: var(--space-1);
}
.trace-conclusion header span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
}
.trace-conclusion h2 {
  font-size: var(--font-size-20);
  margin: 0;
}
.trace-conclusion dl {
  display: grid;
  gap: var(--space-3);
  margin: 0;
}
.trace-conclusion dl > div {
  display: grid;
  gap: var(--space-1);
}
.trace-conclusion dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.trace-conclusion dd {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin: 0;
  overflow-wrap: anywhere;
}
.trace-conclusion code {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-1);
  color: var(--color-text);
  padding: 0 var(--space-2);
}
.trace-body {
  display: grid;
  gap: var(--space-7);
}
.trace-header-actions {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  justify-content: flex-end;
}
.trace-provenance {
  display: grid;
  gap: var(--space-4);
}
.trace-provenance > header {
  align-items: start;
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
  flex-wrap: wrap;
}
.trace-provenance h2,
.trace-provenance p {
  margin: 0;
}
.trace-provenance > header > div > p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin-top: var(--space-1);
}
.provenance-placeholder {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
  margin: 0;
  padding: var(--space-5) 0;
  text-align: center;
}
.trace-layout {
  display: grid;
  gap: clamp(var(--space-5), 3vw, var(--space-7));
  grid-template-columns: minmax(0, 1fr) 16rem;
}
.trace-events {
  display: grid;
  gap: var(--space-5);
}
.trace-events > header {
  align-items: start;
  display: flex;
  justify-content: space-between;
}
.trace-events h2,
.trace-events p {
  margin: 0;
}
.trace-events p,
.trace-events > header > span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.trace-context {
  align-self: start;
  border-left: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  max-height: calc(100vh - var(--top-bar-height) - 6rem);
  overflow-y: auto;
  padding-left: var(--space-5);
  position: sticky;
  top: var(--space-4);
}
.trace-context h2 {
  font-size: var(--font-size-16);
  margin: 0;
}
.trace-context dl {
  display: grid;
  gap: var(--space-3);
  margin: 0;
}
.trace-context dl > div {
  display: grid;
  gap: var(--space-1);
}
.trace-context dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.trace-context dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.trace-context__action {
  justify-self: start;
}
.prov-node-detail {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  padding-top: var(--space-3);
}
.prov-node-detail h3 {
  font-size: var(--font-size-13);
  margin: 0;
}
.prov-node-detail__dl {
  display: grid;
  gap: var(--space-2);
  margin: 0;
}
.prov-node-detail__dl > div {
  display: grid;
  gap: var(--space-1);
}
.prov-node-detail__dl dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.prov-node-detail__dl dd {
  font-size: var(--font-size-13);
  margin: 0;
  overflow-wrap: anywhere;
}
.trace-detail-alert {
  background: var(--color-warning-soft);
  border-left: 3px solid var(--color-warning);
  display: grid;
  gap: var(--space-1);
  margin-bottom: var(--space-4);
  padding: var(--space-3);
}
.trace-detail-alert p {
  color: var(--color-text-muted);
  margin: 0;
}
.inline-retry {
  background: transparent;
  border: 0;
  color: var(--color-link);
  cursor: pointer;
  font-weight: var(--font-weight-semibold);
  justify-self: start;
  min-height: 2rem;
  padding: 0;
}
</style>
