<template>
  <div class="investigations-page">
    <section
      ref="mainPanel"
      class="workspace-panel investigations-page__main"
      aria-labelledby="investigations-title"
    >
      <header class="page-header">
        <div><h1 id="investigations-title">事件调查</h1></div>
        <div class="page-header-actions">
          <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
          <button
            type="button"
            class="page-action"
            :disabled="!filteredEvents.length"
            @click="handleExport"
          >
            <Download aria-hidden="true" :size="15" />
            导出当前筛选结果
          </button>
        </div>
      </header>

      <form class="investigation-tools" role="search" @submit.prevent>
        <label class="investigation-search">
          <span>搜索事件</span>
          <span class="investigation-search__input">
            <Search aria-hidden="true" :size="15" />
            <input
              v-model.trim="searchDraft"
              autocomplete="off"
              name="event-search"
              type="search"
              placeholder="事件 ID、任务、工具、资源、规则或证据链…"
            />
          </span>
        </label>
        <AppSelect
          id="investigation-decision"
          v-model="decisionFilter"
          label="决策"
          :options="decisionOptions"
        />
        <AppSelect
          id="investigation-runtime"
          v-model="runtimeFilter"
          label="运行时"
          :options="runtimeOptions"
        />
        <AppSelect
          id="investigation-severity"
          v-model="severityFilter"
          label="严重性"
          :options="severityOptions"
        />
        <AppSelect
          id="investigation-event-type"
          v-model="eventTypeFilter"
          label="事件类型"
          :options="eventTypeOptions"
        />
        <AppSelect
          id="investigation-attack-type"
          v-model="attackTypeFilter"
          label="攻击类型"
          :options="attackTypeOptions"
        />
        <button v-if="hasFilters" type="button" class="clear-filters" @click="handleClearFilters">
          清除筛选
        </button>
      </form>

      <nav class="quick-filters" aria-label="快速筛选">
        <button
          type="button"
          :aria-pressed="!query.decision && !query.blocked && !query.rule"
          @click="handleQuickFilter({ blocked: '', decision: '', rule: '' })"
        >
          全部 {{ index.latestEvents.length }}
        </button>
        <button
          type="button"
          :aria-pressed="query.decision === 'deny'"
          @click="
            handleQuickFilter({
              blocked: '',
              decision: query.decision === 'deny' ? '' : 'deny',
              rule: '',
            })
          "
        >
          拒绝 {{ deniedCount }}
        </button>
        <button
          v-for="rule in ruleOptions"
          :key="rule.value"
          type="button"
          :aria-pressed="query.rule === rule.value"
          :title="rule.label"
          @click="
            handleQuickFilter({ blocked: '', rule: query.rule === rule.value ? '' : rule.value })
          "
        >
          {{ rule.label }} {{ rule.count }}
        </button>
      </nav>

      <div v-if="pendingNewEventIds.size" class="new-event-notice">
        <span>有 {{ pendingNewEventIds.size }} 条新事件</span>
        <button type="button" @click="handleShowNewEvents">查看新事件</button>
      </div>

      <ErrorState
        v-if="store.status === 'error' && store.error"
        :is-retrying="store.isManualRefreshing"
        :message="store.error"
        @retry="store.refresh"
      />
      <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
      <template v-else-if="filteredEvents.length">
        <div class="result-summary">
          <strong>{{ filteredEvents.length }}</strong
          ><span>条匹配事件</span
          ><span
            >最近最多 {{ AUDIT_EVENT_WINDOW_LIMIT }} 条 · 第 {{ currentPage }} / {{ totalPages }} 页
            · 按最新时间排序</span
          >
        </div>
        <div class="event-table-wrap">
          <table class="event-table">
            <caption>
              调查事件列表
            </caption>
            <thead>
              <tr>
                <th>时间</th>
                <th>决策</th>
                <th>风险</th>
                <th>运行时</th>
                <th>工具与资源</th>
                <th>原因</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="event in paginatedEvents"
                :key="event.id"
                :aria-selected="selectedEvent?.id === event.id"
                :class="{
                  'event-table__new': newEventIds.has(event.id),
                  'event-table__selected': selectedEvent?.id === event.id,
                }"
                tabindex="0"
                @click="handleSelectEvent(event.id)"
                @keydown.enter.prevent="handleSelectEvent(event.id)"
                @keydown.space.prevent="handleSelectEvent(event.id)"
              >
                <td>
                  <span class="event-time">{{ event.time }}</span>
                </td>
                <td>
                  <StatusBadge
                    :label="getDecisionLabel(event.decision)"
                    :tone="getDecisionTone(event.decision)"
                  />
                </td>
                <td>
                  <span class="event-risk" :class="`event-risk--${event.severity}`"
                    ><i
                      :style="{
                        transform: `scaleX(${Math.min(1, Math.max(0, (event.riskScore ?? 0) / 100))})`,
                      }"
                    ></i
                    ><strong
                      ><span>{{ event.riskScore ?? "--" }}</span
                      ><small>{{ getRiskSeverityLabel(event.severity) }}</small></strong
                    ></span
                  >
                </td>
                <td>{{ getRuntimeLabel(event.runtime) }}</td>
                <td>
                  <code>{{ event.tool }}</code
                  ><span class="truncate-cell" :title="event.resource">{{ event.resource }}</span>
                </td>
                <td>
                  <span class="truncate-cell" :title="event.reason">{{ event.reason }}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <footer v-if="totalPages > 1" class="pagination" aria-label="事件分页">
          <span>第 {{ currentPage }} / {{ totalPages }} 页</span>
          <div>
            <button
              type="button"
              :disabled="currentPage === 1"
              @click="handlePage(currentPage - 1)"
            >
              上一页</button
            ><button
              type="button"
              :disabled="currentPage === totalPages"
              @click="handlePage(currentPage + 1)"
            >
              下一页
            </button>
          </div>
        </footer> </template
      ><EmptyState
        v-else
        title="没有匹配事件"
        message="当前条件下没有审计事件，清除筛选后可查看全部已加载记录。"
      >
        <button type="button" @click="handleClearFilters">清除筛选</button>
      </EmptyState>
    </section>

    <DetailDrawer
      :is-open="Boolean(query.eventId)"
      eyebrow="事件详情"
      :title="selectedEvent?.tool ?? '事件未找到'"
      @close="handleCloseEvent"
    >
      <EventEvidence v-if="selectedEvent" :event="selectedEvent">
        <section v-if="selectedTraceEvents.length > 1" class="trace-preview">
          <header>
            <div>
              <h3>关联证据链</h3>
              <span>{{ selectedTraceEvents.length }} 条关联事件</span>
            </div>
            <RouterLink :to="`/evidence/${selectedEvent.traceId}`">查看完整证据链</RouterLink>
          </header>
          <AuditTimeline :events="selectedTraceEvents.slice(0, 4)" />
        </section>
      </EventEvidence>
      <EmptyState v-else title="未找到事件" message="事件可能已离开当前数据窗口。" />
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { Download, Search } from "@lucide/vue";
import {
  computed,
  defineAsyncComponent,
  nextTick,
  onDeactivated,
  onUnmounted,
  ref,
  watch,
} from "vue";
import { useRoute, useRouter } from "vue-router";

import AppSelect from "../components/common/AppSelect.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import DetailDrawer from "../components/common/DetailDrawer.vue";
import EmptyState from "../components/common/EmptyState.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import {
  buildInvestigationIndex,
  filterInvestigationEvents,
  getRuleFilterOptions,
  resolveInvestigationEvent,
} from "../data/investigations";
import { AUDIT_EVENT_WINDOW_LIMIT } from "../data/sources/dashboard-data-source";
import { useDashboardStore } from "../stores/dashboardStore";
import type { AuditEventRow } from "../types/dashboard";
import { getAttackTypeLabel } from "../utils/attack-type";
import { downloadCsv } from "../utils/csv-export";
import {
  getDecisionLabel,
  getDecisionTone,
  getEventTypeLabel,
  getRiskSeverityLabel,
  getRuntimeLabel,
} from "../utils/dashboard-formatters";
import { mergeInvestigationQuery, normalizeInvestigationQuery } from "../utils/investigation-query";
import { formatRuleListForDisplay } from "../utils/rule-display";

defineOptions({ name: "InvestigationsPage" });
const EventEvidence = defineAsyncComponent(
  () => import("../components/evidence/EventEvidence.vue"),
);
const AuditTimeline = defineAsyncComponent(
  () => import("../components/evidence/AuditTimeline.vue"),
);
const PAGE_SIZE = 20;
const route = useRoute();
const router = useRouter();
const store = useDashboardStore();
const mainPanel = ref<HTMLElement | null>(null);
const searchDraft = ref("");
const displayedEvents = ref<AuditEventRow[]>([]);
const newEventIds = ref<ReadonlySet<string>>(new Set());
const pendingNewEventIds = ref<ReadonlySet<string>>(new Set());
let hasEventSnapshot = false;
let knownEventIds = new Set<string>();
let searchTimer: number | undefined;
let newEventTimer: number | undefined;
const query = computed(() => normalizeInvestigationQuery(route.query));
const index = computed(() => buildInvestigationIndex(displayedEvents.value));
const filteredEvents = computed(() => filterInvestigationEvents(index.value, query.value));
const totalPages = computed(() => Math.max(1, Math.ceil(filteredEvents.value.length / PAGE_SIZE)));
const currentPage = computed(() => Math.min(query.value.page, totalPages.value));
const paginatedEvents = computed(() =>
  filteredEvents.value.slice((currentPage.value - 1) * PAGE_SIZE, currentPage.value * PAGE_SIZE),
);
const eventResolution = computed(() => resolveInvestigationEvent(index.value, query.value.eventId));
const selectedEvent = computed(() =>
  eventResolution.value.status === "found" ? eventResolution.value.event : undefined,
);
const selectedTraceEvents = computed(() =>
  selectedEvent.value ? (index.value.byTrace.get(selectedEvent.value.traceId) ?? []) : [],
);
const deniedCount = computed(
  () => index.value.latestEvents.filter((event) => event.decision === "deny").length,
);
const ruleOptions = computed(() => getRuleFilterOptions(index.value.latestEvents).slice(0, 6));
const hasFilters = computed(() =>
  Boolean(
    query.value.search ||
    query.value.decision ||
    query.value.runtime ||
    query.value.severity ||
    query.value.blocked ||
    query.value.rule ||
    query.value.eventType ||
    query.value.stage ||
    query.value.attackType,
  ),
);

const decisionOptions = [
  { label: "全部", value: "" },
  { label: "拒绝", value: "deny" },
  { label: "需审批", value: "ask" },
  { label: "允许", value: "allow" },
];
const runtimeOptions = [
  { label: "全部", value: "" },
  { label: "LangGraph", value: "langgraph" },
  { label: "OpenClaw", value: "openclaw" },
];
const severityOptions = [
  { label: "全部", value: "" },
  { label: "严重", value: "critical" },
  { label: "高", value: "high" },
  { label: "中", value: "medium" },
  { label: "低", value: "low" },
];
function buildDynamicOptions(
  events: typeof index.value.latestEvents,
  key: "eventType" | "attackType",
  getLabel: (value: string) => string = (value) => value,
) {
  const types = new Set(events.map((e) => e[key]).filter((v): v is string => Boolean(v)));
  return [
    { label: "全部", value: "" },
    ...[...types].map((value) => ({ label: getLabel(value), value })),
  ];
}
const eventTypeOptions = computed(() =>
  buildDynamicOptions(index.value.latestEvents, "eventType", getEventTypeLabel),
);
const attackTypeOptions = computed(() =>
  buildDynamicOptions(index.value.latestEvents, "attackType", getAttackTypeLabel),
);

function queryModel(key: "decision" | "runtime" | "severity" | "eventType" | "attackType") {
  return computed({
    get: () => query.value[key],
    set: (value: string) => updateQuery({ [key]: value, page: 1 }),
  });
}
const decisionFilter = queryModel("decision");
const runtimeFilter = queryModel("runtime");
const severityFilter = queryModel("severity");
const eventTypeFilter = queryModel("eventType");
const attackTypeFilter = queryModel("attackType");

watch(
  () => query.value.search,
  (value) => {
    if (route.name === "investigations" && value !== searchDraft.value) searchDraft.value = value;
  },
  { immediate: true },
);
watch(searchDraft, (value) => {
  window.clearTimeout(searchTimer);
  if (route.name !== "investigations") return;
  searchTimer = window.setTimeout(() => {
    if (route.name === "investigations") updateQuery({ search: value, page: 1 });
  }, 250);
});
watch(
  [() => store.events, () => store.status],
  ([events, status]) => {
    if (!hasEventSnapshot) {
      if ((status === "idle" || status === "loading") && !events.length) return;
      displayedEvents.value = events;
      knownEventIds = new Set(events.map((event) => event.id));
      hasEventSnapshot = true;
      return;
    }

    const incomingIds = events
      .map((event) => event.id)
      .filter((eventId) => !knownEventIds.has(eventId));
    knownEventIds = new Set(events.map((event) => event.id));

    if (!incomingIds.length && !pendingNewEventIds.value.size) {
      displayedEvents.value = events;
      return;
    }

    if (!incomingIds.length) {
      updateDisplayedEvents(events);
      return;
    }

    const isAtTop = window.scrollY <= getMainPanelScrollTop() + 40;
    if (isAtTop && !pendingNewEventIds.value.size) {
      displayedEvents.value = events;
      highlightNewEvents(incomingIds);
      return;
    }

    updateDisplayedEvents(events);
    pendingNewEventIds.value = new Set([...pendingNewEventIds.value, ...incomingIds]);
  },
  { immediate: true },
);

function updateDisplayedEvents(events: AuditEventRow[]) {
  const incomingById = new Map(events.map((event) => [event.id, event]));
  displayedEvents.value = displayedEvents.value
    .map((event) => incomingById.get(event.id))
    .filter((event): event is AuditEventRow => event !== undefined);
}

function highlightNewEvents(eventIds: string[]) {
  window.clearTimeout(newEventTimer);
  newEventIds.value = new Set(eventIds);
  newEventTimer = window.setTimeout(() => {
    newEventIds.value = new Set();
  }, 900);
}

async function handleShowNewEvents() {
  const eventIds = [...pendingNewEventIds.value];
  pendingNewEventIds.value = new Set();
  displayedEvents.value = store.events;
  updateQuery({ page: 1 });
  highlightNewEvents(eventIds);
  await nextTick();
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  window.scrollTo({
    behavior: reduceMotion ? "auto" : "smooth",
    top: getMainPanelScrollTop(),
  });
}

function getMainPanelScrollTop(): number {
  if (!mainPanel.value) return 0;
  const panelTop = mainPanel.value.getBoundingClientRect().top + window.scrollY;
  const topBarHeight = document
    .querySelector<HTMLElement>(".top-bar")
    ?.getBoundingClientRect().height;
  return Math.max(0, panelTop - (topBarHeight ?? 0));
}

function clearTimers() {
  window.clearTimeout(searchTimer);
  window.clearTimeout(newEventTimer);
  newEventIds.value = new Set();
}
onDeactivated(() => {
  clearTimers();
  displayedEvents.value = store.events;
  pendingNewEventIds.value = new Set();
  knownEventIds = new Set(store.events.map((event) => event.id));
  hasEventSnapshot = store.status !== "loading" || Boolean(store.events.length);
});
onUnmounted(clearTimers);

function updateQuery(patch: Record<string, string | number | undefined>) {
  if (route.name !== "investigations") return;
  void router.replace({
    path: "/investigations",
    query: mergeInvestigationQuery(route.query, patch),
  });
}
function handleSelectEvent(eventId: string) {
  updateQuery({ event_id: eventId });
}
function handleCloseEvent() {
  updateQuery({ event_id: undefined });
}
function handlePage(page: number) {
  updateQuery({ page });
}
function handleQuickFilter(patch: Record<string, string>) {
  updateQuery({ ...patch, page: 1 });
}
function handleClearFilters() {
  searchDraft.value = "";
  void router.replace({
    path: "/investigations",
    query: query.value.eventId ? { event_id: query.value.eventId } : {},
  });
}
function handleExport() {
  const headers = [
    "时间",
    "决策",
    "严重性",
    "风险分",
    "运行时",
    "阶段",
    "事件类型",
    "工具",
    "资源",
    "原因",
    "证据链 ID",
    "Case ID",
    "规则命中",
  ];
  const rows = filteredEvents.value.map((e) => [
    e.occurredAt,
    getDecisionLabel(e.decision),
    getRiskSeverityLabel(e.severity),
    e.riskScore,
    e.runtime,
    e.stage,
    e.eventType,
    e.tool,
    e.resource,
    e.reason,
    e.traceId,
    e.caseId ?? "",
    formatRuleListForDisplay(e.ruleHits),
  ]);
  downloadCsv(`audit-events-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
}
</script>

<style scoped lang="scss">
.investigations-page {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
}
.investigations-page__main {
  min-width: 0;
}
.investigation-tools {
  align-items: end;
  border-block: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(14rem, 1.4fr) repeat(5, minmax(6.25rem, 0.5fr)) auto;
  padding: var(--space-4) 0;
}
.page-header-actions {
  align-items: center;
  display: flex;
  gap: var(--space-3);
}
.investigation-search {
  color: var(--color-text-muted);
  display: grid;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-1);
}
.investigation-search__input {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-text-subtle);
  display: flex;
  gap: var(--space-2);
  min-height: 2.5rem;
  padding: 0 var(--space-3);
  width: 100%;
}
.investigation-search__input:focus-within {
  border-color: var(--color-active-border);
  box-shadow: var(--glow-active);
}
.investigation-search input {
  background: transparent;
  border: 0;
  color: var(--color-text);
  min-width: 0;
  outline: 0;
  padding: 0;
  width: 100%;
}
.clear-filters {
  background: transparent;
  border: 0;
  color: var(--color-link);
  cursor: pointer;
  min-height: 2.5rem;
}
.quick-filters {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  padding: var(--space-3) 0 var(--space-5);
}
.quick-filters button {
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text-muted);
  cursor: pointer;
  font-size: var(--font-size-12);
  max-width: 16rem;
  min-height: 2.25rem;
  overflow: hidden;
  padding: 0 var(--space-3);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.quick-filters button[aria-pressed="true"] {
  background: var(--color-active-soft);
  border-color: var(--color-active-border);
  color: var(--color-active-strong);
  font-weight: var(--font-weight-semibold);
}
.new-event-notice {
  align-items: center;
  background: var(--color-active-soft);
  border-left: 3px solid var(--color-active);
  color: var(--color-active-strong);
  display: flex;
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-3);
  justify-content: space-between;
  margin-bottom: var(--space-4);
  padding: var(--space-2) var(--space-3);
}
.new-event-notice button {
  background: var(--color-surface);
  border: 1px solid var(--color-active-border);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  font-weight: var(--font-weight-bold);
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}
.result-summary {
  align-items: baseline;
  display: flex;
  gap: var(--space-2);
  padding-bottom: var(--space-2);
}
.result-summary span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.result-summary span:last-child {
  margin-left: auto;
}
.event-table-wrap {
  border-top: 1px solid var(--color-border-strong);
  overflow-x: auto;
}
.event-table {
  border-collapse: collapse;
  min-width: 54rem;
  width: 100%;
}
.event-table caption {
  height: 1px;
  overflow: hidden;
  position: absolute;
  width: 1px;
}
.event-table th,
.event-table td {
  border-bottom: 1px solid var(--color-border);
  font-size: var(--font-size-13);
  max-width: 18rem;
  padding: var(--space-3);
  text-align: left;
  vertical-align: middle;
}
.event-table th {
  background: color-mix(in srgb, var(--color-page) 92%, var(--color-surface));
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  letter-spacing: 0.03em;
  position: sticky;
  top: 0;
  text-transform: uppercase;
  z-index: 2;
}
.event-table tbody tr {
  cursor: pointer;
}
.event-table td:first-child {
  position: relative;
}
.event-table__new td:first-child::before {
  animation: event-arrival 900ms var(--ease-emphasis) both;
  background: var(--color-active);
  content: "";
  inset: var(--space-2) auto var(--space-2) 0;
  position: absolute;
  transform-origin: center;
  width: 2px;
}
.event-table tbody tr:hover,
.event-table tbody tr:focus-visible,
.event-table__selected {
  background: var(--color-row-selected);
}
.event-table tbody tr:focus-visible {
  box-shadow: inset 0 0 0 2px var(--color-focus);
  outline: 0;
}
.event-table__selected {
  box-shadow: inset 2px 0 var(--color-active);
}
.event-time {
  color: var(--color-link);
  font-weight: var(--font-weight-semibold);
}
.event-table td:nth-child(5) {
  display: grid;
  gap: var(--space-1);
}
.event-risk {
  align-items: center;
  display: grid;
  gap: var(--space-2);
  grid-template-columns: minmax(2.5rem, 1fr) auto;
}
.event-risk strong {
  align-items: baseline;
  display: flex;
  gap: var(--space-1);
  white-space: nowrap;
}
.event-risk small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.event-risk::before {
  background: var(--color-surface-muted);
  content: "";
  grid-column: 1;
  grid-row: 1;
  height: 0.25rem;
}
.event-risk i {
  background: var(--gradient-data-active);
  grid-column: 1;
  grid-row: 1;
  height: 0.25rem;
  max-width: 100%;
  transform-origin: left;
  transition: transform var(--transition-data);
}
.event-risk--critical i,
.event-risk--high i {
  background: var(--gradient-data-danger);
}
.event-risk--medium i {
  background: var(--gradient-data-warning);
}
.pagination {
  align-items: center;
  color: var(--color-text-muted);
  display: flex;
  font-size: var(--font-size-12);
  justify-content: space-between;
  padding-top: var(--space-4);
}
.pagination div {
  display: flex;
  gap: var(--space-2);
}
.pagination button {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}
.pagination button:disabled {
  opacity: 0.45;
}
.trace-preview {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  padding-top: var(--space-4);
}
.trace-preview > header {
  align-items: start;
  display: flex;
  justify-content: space-between;
}

@media (max-width: 74.9375rem) {
  .investigation-tools {
    grid-template-columns: repeat(3, minmax(10rem, 1fr));
  }

  .investigation-search {
    grid-column: 1 / -1;
  }

  .event-table-wrap {
    max-width: 100%;
    overscroll-behavior-inline: contain;
  }
}

@media (max-width: 56.25rem) {
  .investigation-tools {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .page-header-actions,
  .new-event-notice,
  .pagination,
  .result-summary {
    flex-wrap: wrap;
  }

  .result-summary span:last-child {
    margin-left: 0;
    width: 100%;
  }
}
.trace-preview h3 {
  margin: 0;
}
.trace-preview header span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}

@keyframes event-arrival {
  0% {
    opacity: 0;
    transform: scaleY(0.2);
  }
  28% {
    opacity: 1;
    transform: scaleY(1);
  }
  100% {
    opacity: 0;
    transform: scaleY(1);
  }
}
</style>
