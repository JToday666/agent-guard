<template>
  <div class="evidence-detail">
    <section class="workspace-panel evidence-detail__main" aria-labelledby="trace-title">
      <header class="page-header evidence-page-header">
        <div>
          <h1 id="trace-title">证据链详情</h1>
          <p>查看任务从输入到执行结果的关键证据。</p>
        </div>
        <div class="trace-header-actions">
          <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
          <RouterLink class="page-action" to="/evidence">返回证据链</RouterLink>
        </div>
      </header>

      <InlineNotice
        v-if="traceDetailError && traceEvents.length"
        class="trace-detail-alert"
        title="证据刷新未完成"
        tone="warning"
      >
        <p>{{ traceDetailError }}。当前保留上次成功数据或已加载的近期记录，证据可能不完整。</p>
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

      <template v-else-if="traceEvents.length">
        <section
          class="evidence-hero"
          :class="`evidence-hero--${evidenceModel.conclusion.confidence}`"
          aria-labelledby="evidence-conclusion-title"
        >
          <div class="evidence-hero__meta">
            <span
              >证据链 <code>{{ traceId }}</code></span
            >
            <span
              >评测样本 <code>{{ evidenceModel.caseId ?? "未记录" }}</code></span
            >
            <span
              >时间范围 <time>{{ traceRange }}</time></span
            >
            <span>
              审计记录 {{ evidenceModel.originalAuditCount }} 条 · 去重后
              {{ evidenceModel.logicalAuditCount }} 条
            </span>
          </div>
          <div class="evidence-hero__body">
            <div class="evidence-hero__signal" aria-hidden="true">
              <ShieldAlert :size="28" stroke-width="1.6" />
            </div>
            <div>
              <span>{{ conclusionConfidenceLabel }}</span>
              <h2 id="evidence-conclusion-title">{{ evidenceModel.conclusion.title }}</h2>
              <p>{{ evidenceModel.conclusion.reason }}</p>
            </div>
            <div class="evidence-hero__outcome">
              <span>最终结果</span>
              <strong>{{ evidenceModel.conclusion.outcome }}</strong>
            </div>
          </div>
          <footer>
            <div v-if="primaryRules.length">
              <span>关键规则</span>
              <code v-for="rule in primaryRules" :key="rule.ruleId">
                {{ rule.name ?? ruleLabel(rule.ruleId) }}
              </code>
            </div>
            <div class="evidence-hero__links">
              <RouterLink
                v-if="evidenceModel.primary?.approval.approvalId"
                class="page-action"
                :to="`/approvals/${evidenceModel.primary.approval.approvalId}`"
              >
                查看关联审批
              </RouterLink>
              <RouterLink
                v-if="evidenceModel.caseId"
                class="page-action"
                :to="{ path: '/evaluation', query: { case_id: evidenceModel.caseId } }"
              >
                查看评测样本
              </RouterLink>
            </div>
          </footer>
        </section>

        <EvidenceFactStrip :facts="evidenceModel.facts" />

        <section class="evidence-stage-section" aria-labelledby="evidence-stage-title">
          <header class="section-header">
            <div>
              <h2 id="evidence-stage-title">关键证据路径</h2>
              <p>查看输入来源、任务意图、安全判断和执行结果；缺失信息明确标记为未记录。</p>
            </div>
          </header>
          <EvidenceStageFlow
            :stages="evidenceModel.stages"
            @select-event="handleTimelineSelectEvent"
          />
        </section>

        <section class="trace-provenance section-divider" aria-labelledby="provenance-title">
          <header class="section-header">
            <div>
              <h2 id="provenance-title">攻击溯源关系</h2>
              <p>查看任务、来源、动作、资源、安全规则与执行结果之间的关联。</p>
            </div>
            <span v-if="provenance" class="trace-provenance__count">
              {{ provenance.nodes.length }} 节点 · {{ provenance.edges.length }} 关系
            </span>
          </header>
          <InlineNotice v-if="provenanceError" title="溯源关系刷新未完成" tone="warning">
            <p>{{ provenanceError }}</p>
            <button class="inline-retry" type="button" @click="handleProvenanceRetry">
              重新加载溯源关系
            </button>
          </InlineNotice>
          <div v-if="provenance" class="provenance-layout">
            <ProvenanceGraph
              :key="traceId"
              :graph="provenance"
              :selected-node-id="selectedProvenanceNodeId"
              @select-node="handleSelectProvenanceNode"
            />
            <ProvenanceInspector
              :event-ids="traceEvents.map((event) => event.id)"
              :graph="provenance"
              :node="selectedProvenanceNode"
              @select-event="handleTimelineSelectEvent"
            />
          </div>
          <p v-else-if="!provenanceError" class="provenance-placeholder">正在加载溯源关系…</p>
        </section>

        <section class="trace-records section-divider" aria-labelledby="trace-records-title">
          <header class="section-header">
            <div>
              <h2 id="trace-records-title">事件时间线与详细证据</h2>
              <p>按发生顺序查看全部审计记录；重复的策略记录只在结论汇总中合并。</p>
            </div>
          </header>
          <div class="trace-records__layout">
            <section class="trace-events" aria-labelledby="trace-events-title">
              <header>
                <h3 id="trace-events-title">事件时间线</h3>
                <span>{{ traceEvents.length }} 条审计记录</span>
              </header>
              <TraceTimeline
                :events="traceEvents"
                :normalized-events="evidenceModel.events"
                :selected-event-id="selectedEventId"
                :trace-id="traceId"
                @select-event="handleTimelineSelectEvent"
              />
            </section>
            <aside class="trace-dossier" aria-label="规则、风险、策略和原始证据">
              <EvidenceDossier :evidence="evidenceModel" />
            </aside>
          </div>
        </section>
      </template>

      <EmptyState v-else title="未找到证据链" message="该证据链不存在，或已经离开当前数据窗口。">
        <RouterLink to="/evidence">返回证据链</RouterLink>
      </EmptyState>
    </section>

    <DetailDrawer
      :is-open="isEventDrawerOpen"
      eyebrow="事件详情"
      :title="selectedEvent?.tool ?? '事件未找到'"
      @close="handleCloseEvidence"
    >
      <EventEvidence
        v-if="selectedEvent"
        :event="selectedEvent"
        :normalized="selectedNormalizedEvent"
      />
      <EmptyState
        v-else
        title="未找到事件"
        message="该事件不存在、已离开当前数据窗口，或不属于当前证据链。"
      />
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { ShieldAlert } from "@lucide/vue";
import { computed, defineAsyncComponent, nextTick, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import DataFreshness from "../components/common/DataFreshness.vue";
import DetailDrawer from "../components/common/DetailDrawer.vue";
import EmptyState from "../components/common/EmptyState.vue";
import InlineNotice from "../components/common/InlineNotice.vue";
import EvidenceDossier from "../components/evidence/EvidenceDossier.vue";
import EvidenceFactStrip from "../components/evidence/EvidenceFactStrip.vue";
import EvidenceStageFlow from "../components/evidence/EvidenceStageFlow.vue";
import EventEvidence from "../components/evidence/EventEvidence.vue";
import ProvenanceInspector from "../components/evidence/ProvenanceInspector.vue";
import TraceTimeline from "../components/evidence/TraceTimeline.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { buildTraceEvidenceViewModel } from "../data/evidence/trace-evidence";
import { buildInvestigationIndex, resolveInvestigationEvent } from "../data/investigations";
import { useDashboardStore } from "../stores/dashboardStore";
import type { ProvenanceNode } from "../types/dashboard";
import { formatDashboardDateTime } from "../utils/dashboard-formatters";
import { mergeInvestigationQuery } from "../utils/investigation-query";
import { findProvenanceNodeForEvent, resolveProvenanceEventId } from "../utils/provenance";
import { ruleLabel } from "../utils/rule-display";

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
const traceApprovals = computed(() =>
  traceDetail.value
    ? traceDetail.value.approvals
    : store.approvals.filter((approval) => approval.traceId === traceId.value),
);
const evidenceModel = computed(() =>
  buildTraceEvidenceViewModel(
    traceId.value,
    traceEvents.value,
    traceApprovals.value,
    store.auditIntegrity,
  ),
);
const detailIndex = computed(() => buildInvestigationIndex(traceEvents.value));
const selectedEventId = computed(() =>
  typeof route.query.event_id === "string" ? route.query.event_id : "",
);
const eventResolution = computed(() =>
  resolveInvestigationEvent(detailIndex.value, selectedEventId.value, traceId.value),
);
const selectedEvent = computed(() =>
  eventResolution.value.status === "found" ? eventResolution.value.event : undefined,
);
const selectedNormalizedEvent = computed(() =>
  evidenceModel.value.events.find((event) => event.auditId === selectedEventId.value),
);
const provenance = computed(() => store.provenanceByTrace[traceId.value]);
const provenanceError = computed(() => store.provenanceErrors[traceId.value] ?? "");
const selectedProvenanceNodeId = computed<string | undefined>(() =>
  typeof route.query.prov_node === "string" ? route.query.prov_node : undefined,
);
const selectedProvenanceNode = computed<ProvenanceNode | undefined>(() =>
  provenance.value?.nodes.find((node) => node.nodeId === selectedProvenanceNodeId.value),
);
const eventDetailRequested = computed(() => route.query.event_detail === "1");
const isEventDrawerOpen = computed(() =>
  Boolean(selectedEventId.value && (eventDetailRequested.value || !selectedProvenanceNodeId.value)),
);
const primaryRules = computed(() => evidenceModel.value.primary?.ruleHits.slice(0, 3) ?? []);
const traceRange = computed(() => {
  const start = evidenceModel.value.startedAt;
  const end = evidenceModel.value.endedAt;
  if (!start && !end) return "未记录";
  if (!start || start === end) return formatDashboardDateTime(start ?? end ?? "");
  return `${formatDashboardDateTime(start)} — ${formatDashboardDateTime(end ?? start)}`;
});
const conclusionConfidenceLabel = computed(() => {
  if (evidenceModel.value.conclusion.confidence === "confirmed") return "证据确认";
  if (evidenceModel.value.conclusion.confidence === "partial") return "部分证据";
  return "证据不足";
});

function handleSelectProvenanceNode(nodeId: string) {
  const node = provenance.value?.nodes.find((item) => item.nodeId === nodeId);
  const eventId = resolveProvenanceEventId(node, traceEvents.value);
  void router.replace({
    path: `/evidence/${traceId.value}`,
    query: mergeInvestigationQuery(route.query, {
      event_detail: undefined,
      event_id: eventId,
      prov_node: nodeId,
    }),
  });
}

function handleTimelineSelectEvent(eventId: string) {
  const matchNode = findProvenanceNodeForEvent(provenance.value?.nodes ?? [], eventId);
  void router.replace({
    path: `/evidence/${traceId.value}`,
    query: mergeInvestigationQuery(route.query, {
      event_detail: "1",
      event_id: eventId,
      prov_node: matchNode?.nodeId,
    }),
  });
}

function handleCloseEvidence() {
  void router.replace({
    path: `/evidence/${traceId.value}`,
    query: mergeInvestigationQuery(route.query, {
      event_detail: undefined,
      event_id: undefined,
    }),
  });
}

function handleTraceRetry() {
  void store.loadTraceDetail(traceId.value, true);
}

function handleProvenanceRetry() {
  void store.loadTraceProvenance(traceId.value, true);
}

watch(
  [selectedEventId, traceEvents, selectedProvenanceNodeId, eventDetailRequested],
  async ([eventId, , nodeId, detailRequested]) => {
    if (!eventId || (nodeId && !detailRequested)) return;
    await nextTick();
    document
      .querySelector<HTMLElement>(`[data-event-id="${CSS.escape(eventId)}"]`)
      ?.scrollIntoView({ block: "center" });
  },
  { immediate: true },
);

watch([selectedEventId, provenance, selectedProvenanceNodeId], ([eventId, graph, nodeId]) => {
  if (!eventId || !graph || nodeId) return;
  const node = findProvenanceNodeForEvent(graph.nodes, eventId);
  if (!node) return;
  void router.replace({
    path: `/evidence/${traceId.value}`,
    query: mergeInvestigationQuery(route.query, {
      event_detail: "1",
      prov_node: node.nodeId,
    }),
  });
});

watch(
  traceId,
  (value) => {
    if (!value) return;
    void store.loadTraceDetail(value);
    void store.loadTraceProvenance(value);
  },
  { immediate: true },
);
</script>

<style scoped lang="scss">
.evidence-detail {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  height: calc(100vh - var(--top-bar-height));
  overflow: hidden;
}

.evidence-detail__main {
  align-content: start;
  display: grid;
  gap: var(--space-6);
  grid-auto-rows: max-content;
  min-height: 0;
  min-width: 0;
  overflow-y: auto;
}

.evidence-page-header {
  margin-bottom: 0;
}

.evidence-page-header > div:first-child {
  display: grid;
  gap: var(--space-1);
}

.evidence-page-header p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  padding-left: calc(var(--space-3) + 0.25rem);
}

.trace-header-actions {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  justify-content: flex-end;
}

.evidence-hero {
  --hero-accent: var(--color-active);
  background: linear-gradient(
    112deg,
    color-mix(in srgb, var(--hero-accent) 11%, var(--color-surface)) 0%,
    var(--color-surface) 48%
  );
  border: 1px solid var(--color-border);
  border-left: 4px solid var(--hero-accent);
  border-radius: var(--radius-2);
  display: grid;
  overflow: hidden;
}

.evidence-hero--partial {
  --hero-accent: var(--color-warning);
}

.evidence-hero--unknown {
  --hero-accent: var(--color-chart-slate);
}

.evidence-hero__meta {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2) var(--space-5);
  padding: var(--space-2) var(--space-4);
}

.evidence-hero__meta > span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
}

.evidence-hero__body {
  align-items: center;
  display: grid;
  gap: var(--space-4);
  grid-template-columns: auto minmax(0, 1fr) minmax(18rem, 0.75fr);
  padding: var(--space-5);
}

.evidence-hero__signal {
  align-items: center;
  background: color-mix(in srgb, var(--hero-accent) 12%, var(--color-surface));
  border: 1px solid color-mix(in srgb, var(--hero-accent) 34%, var(--color-border));
  border-radius: var(--radius-2);
  color: var(--hero-accent);
  display: flex;
  height: 3.5rem;
  justify-content: center;
  width: 3.5rem;
}

.evidence-hero__body > div:nth-child(2) {
  display: grid;
  gap: var(--space-1);
}

.evidence-hero__body > div:nth-child(2) > span,
.evidence-hero__outcome > span,
.evidence-hero footer > div > span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.evidence-hero h2,
.evidence-hero p {
  margin: 0;
}

.evidence-hero h2 {
  color: var(--color-text);
  font-size: clamp(var(--font-size-20), 2vw, var(--font-size-24));
}

.evidence-hero p {
  color: var(--color-text-muted);
}

.evidence-hero__outcome {
  border-left: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-2);
  padding-left: var(--space-5);
}

.evidence-hero__outcome strong {
  font-size: var(--font-size-13);
  line-height: 1.6;
}

.evidence-hero footer {
  align-items: center;
  border-top: 1px solid var(--color-border);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  justify-content: space-between;
  padding: var(--space-3) var(--space-4);
}

.evidence-hero footer > div:first-child {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.evidence-hero footer code {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-1);
  padding: 0.1rem var(--space-2);
}

.evidence-hero__links {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.evidence-stage-section,
.trace-provenance,
.trace-records {
  display: grid;
  gap: var(--space-4);
}

.trace-provenance__count {
  color: var(--color-text-subtle);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
}

.provenance-layout {
  align-items: stretch;
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(0, 1fr) 16rem;
  min-width: 0;
}

.provenance-placeholder {
  color: var(--color-text-subtle);
  margin: 0;
  padding: var(--space-8);
  text-align: center;
}

.trace-records__layout {
  align-items: start;
  display: grid;
  gap: clamp(var(--space-5), 3vw, var(--space-7));
  grid-template-columns: minmax(20rem, 0.8fr) minmax(26rem, 1.2fr);
}

.trace-events,
.trace-dossier {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  min-width: 0;
  padding: var(--space-4);
}

.trace-events {
  display: grid;
  gap: var(--space-5);
}

.trace-events > header {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  display: flex;
  justify-content: space-between;
  padding-bottom: var(--space-3);
}

.trace-events h3 {
  font-size: var(--font-size-14);
  margin: 0;
}

.trace-events > header span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.trace-detail-alert {
  background: var(--color-warning-soft);
  border-left: 3px solid var(--color-warning);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-3);
}

.trace-detail-alert p {
  color: var(--color-text-muted);
  margin: 0;
}

.inline-retry {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid currentColor;
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  display: inline-flex;
  font-weight: var(--font-weight-semibold);
  justify-self: start;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}

@media (max-width: 82rem) {
  .provenance-layout {
    grid-template-columns: 1fr;
  }

  .trace-records__layout {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 62rem) {
  .evidence-hero__body {
    align-items: start;
    grid-template-columns: auto minmax(0, 1fr);
  }

  .evidence-hero__outcome {
    border-left: 0;
    border-top: 1px solid var(--color-border);
    grid-column: 1 / -1;
    padding: var(--space-4) 0 0;
  }
}

@media (max-width: 48rem) {
  .evidence-page-header {
    align-items: start;
    flex-direction: column;
  }

  .trace-header-actions {
    justify-content: flex-start;
  }

  .evidence-hero__body {
    grid-template-columns: 1fr;
  }

  .evidence-hero__outcome {
    grid-column: auto;
  }
}
</style>
