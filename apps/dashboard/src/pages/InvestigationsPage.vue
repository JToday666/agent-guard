<template>
  <div class="investigations-page" :class="{ 'investigations-page--detail': Boolean(selectedEvent) }">
    <main class="workspace-panel investigations-page__main" aria-labelledby="investigations-title">
      <header class="page-header">
        <div><h1 id="investigations-title">事件调查</h1></div>
        <div class="page-header-actions">
          <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
          <button type="button" class="page-action" :disabled="!filteredEvents.length" @click="handleExport">导出 CSV</button>
        </div>
      </header>

      <form class="investigation-tools" role="search" @submit.prevent>
        <label class="investigation-search">
          <span>搜索事件</span>
          <input v-model.trim="searchDraft" type="search" placeholder="资源、规则名称、原因、证据链或 Case" />
        </label>
        <AppSelect id="investigation-decision" v-model="decisionFilter" label="决策" :options="decisionOptions" />
        <AppSelect id="investigation-runtime" v-model="runtimeFilter" label="运行时" :options="runtimeOptions" />
        <AppSelect id="investigation-severity" v-model="severityFilter" label="严重性" :options="severityOptions" />
        <AppSelect id="investigation-event-type" v-model="eventTypeFilter" label="事件类型" :options="eventTypeOptions" />
        <AppSelect id="investigation-attack-type" v-model="attackTypeFilter" label="攻击类型" :options="attackTypeOptions" />
        <button v-if="hasFilters" type="button" class="clear-filters" @click="handleClearFilters">清除筛选</button>
      </form>

      <nav class="quick-filters" aria-label="快速筛选">
        <button type="button" :aria-pressed="!query.blocked && !query.rule" @click="handleQuickFilter({ blocked: '', rule: '' })">全部 {{ index.latestEvents.length }}</button>
        <button type="button" :aria-pressed="query.blocked === 'true'" @click="handleQuickFilter({ blocked: query.blocked === 'true' ? '' : 'true', rule: '' })">已阻断 {{ blockedCount }}</button>
        <button v-for="rule in ruleOptions" :key="rule.value" type="button" :aria-pressed="query.rule === rule.value" :title="ruleLabel(rule.value)" @click="handleQuickFilter({ blocked: '', rule: query.rule === rule.value ? '' : rule.value })">{{ ruleOptionLabel(rule.value, rule.count) }}</button>
      </nav>

      <ErrorState v-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="store.refresh" />
      <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
      <template v-else-if="filteredEvents.length">
        <div class="result-summary"><strong>{{ filteredEvents.length }}</strong><span>条匹配事件</span><span>按最新时间排序</span></div>
        <div class="event-table-wrap">
          <table class="event-table">
            <caption>调查事件列表</caption>
            <thead><tr><th>时间</th><th>决策</th><th>风险</th><th>运行时</th><th>工具与资源</th><th>原因</th></tr></thead>
            <tbody>
              <tr
                v-for="event in paginatedEvents"
                :key="event.id"
                :aria-selected="selectedEvent?.id === event.id"
                :class="{ 'event-table__selected': selectedEvent?.id === event.id }"
                tabindex="0"
                @click="handleSelectEvent(event.id)"
                @keydown.enter.prevent="handleSelectEvent(event.id)"
                @keydown.space.prevent="handleSelectEvent(event.id)"
              >
                <td><span class="event-time">{{ event.time }}</span></td>
                <td><StatusBadge :label="getDecisionLabel(event.decision)" :tone="getDecisionTone(event.decision)" /></td>
                <td><span class="event-risk" :class="`event-risk--${event.severity}`"><i :style="{ width: `${event.riskScore}%` }"></i><strong>{{ event.riskScore }}</strong></span></td>
                <td>{{ event.runtime }}</td>
                <td><code>{{ event.tool }}</code><span class="truncate-cell" :title="event.resource">{{ event.resource }}</span></td>
                <td><span class="truncate-cell" :title="event.reason">{{ event.reason }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
        <footer v-if="totalPages > 1" class="pagination" aria-label="事件分页">
          <span>第 {{ currentPage }} / {{ totalPages }} 页</span>
          <div><button type="button" :disabled="currentPage === 1" @click="handlePage(currentPage - 1)">上一页</button><button type="button" :disabled="currentPage === totalPages" @click="handlePage(currentPage + 1)">下一页</button></div>
        </footer>
      </template>
      <EmptyState v-else title="没有匹配事件" message="当前条件下没有审计事件，清除筛选后可查看完整记录。"><button type="button" @click="handleClearFilters">清除筛选</button></EmptyState>
    </main>

    <DetailDrawer :is-open="Boolean(query.eventId)" eyebrow="事件证据" :title="selectedEvent?.tool ?? '事件未找到'" @close="handleCloseEvent">
      <EventEvidence v-if="selectedEvent" :event="selectedEvent">
        <section v-if="selectedTraceEvents.length > 1" class="trace-preview">
          <header><div><h3>关联证据链</h3><span>{{ selectedTraceEvents.length }} 个事件节点</span></div><RouterLink :to="`/evidence/${selectedEvent.traceId}`">查看完整证据链</RouterLink></header>
          <TraceTimeline :events="selectedTraceEvents.slice(0, 4)" />
        </section>
      </EventEvidence>
      <EmptyState v-else title="未找到事件" message="事件可能已离开当前数据窗口。" />
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, onDeactivated, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import AppSelect from "../components/AppSelect.vue";
import DataFreshness from "../components/DataFreshness.vue";
import DetailDrawer from "../components/DetailDrawer.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/States/ErrorState.vue";
import LoadingState from "../components/States/LoadingState.vue";
import { filterInvestigationEvents, getRuleFilterOptions, resolveInvestigationEvent } from "../data/investigation-index";
import { useDashboardStore } from "../stores/dashboardStore";
import { getDecisionLabel, getDecisionTone } from "../utils/dashboard-formatters";
import { mergeInvestigationQuery, normalizeInvestigationQuery } from "../utils/investigation-query";
import { formatRuleListForDisplay, ruleLabel, ruleOptionLabel } from "../utils/rule-display";

defineOptions({ name: "InvestigationsPage" });
const EventEvidence = defineAsyncComponent(() => import("../components/EventEvidence.vue"));
const TraceTimeline = defineAsyncComponent(() => import("../components/TraceTimeline.vue"));
const PAGE_SIZE = 20;
const route = useRoute();
const router = useRouter();
const store = useDashboardStore();
const searchDraft = ref("");
let searchTimer: number | undefined;
const query = computed(() => normalizeInvestigationQuery(route.query));
const index = computed(() => store.investigationIndex);
const filteredEvents = computed(() => filterInvestigationEvents(index.value, query.value));
const totalPages = computed(() => Math.max(1, Math.ceil(filteredEvents.value.length / PAGE_SIZE)));
const currentPage = computed(() => Math.min(query.value.page, totalPages.value));
const paginatedEvents = computed(() => filteredEvents.value.slice((currentPage.value - 1) * PAGE_SIZE, currentPage.value * PAGE_SIZE));
const eventResolution = computed(() => resolveInvestigationEvent(index.value, query.value.eventId));
const selectedEvent = computed(() => eventResolution.value.status === "found" ? eventResolution.value.event : undefined);
const selectedTraceEvents = computed(() => selectedEvent.value ? index.value.byTrace.get(selectedEvent.value.traceId) ?? [] : []);
const blockedCount = computed(() => index.value.latestEvents.filter((event) => event.blocked).length);
const ruleOptions = computed(() => getRuleFilterOptions(index.value.latestEvents).slice(0, 6));
const hasFilters = computed(() => Boolean(
  query.value.search || query.value.decision || query.value.runtime ||
  query.value.severity || query.value.blocked || query.value.rule ||
  query.value.eventType || query.value.attackType
));

const decisionOptions = [{ label: "全部", value: "" }, { label: "拒绝", value: "deny" }, { label: "审批", value: "ask" }, { label: "放行", value: "allow" }];
const runtimeOptions = [{ label: "全部", value: "" }, { label: "LangGraph", value: "langgraph" }, { label: "OpenClaw", value: "openclaw" }];
const severityOptions = [{ label: "全部", value: "" }, { label: "严重", value: "critical" }, { label: "高", value: "high" }, { label: "中", value: "medium" }, { label: "低", value: "low" }];
const eventTypeOptions = computed(() => {
  const types = new Set(index.value.latestEvents.map((e) => e.eventType).filter(Boolean));
  return [{ label: "全部", value: "" }, ...([...types].map((v) => ({ label: v, value: v })))];
});
const attackTypeOptions = computed(() => {
  const types = new Set(index.value.latestEvents.map((e) => e.attackType).filter((v): v is string => Boolean(v)));
  return [{ label: "全部", value: "" }, ...([...types].map((v) => ({ label: v, value: v })))];
});

function queryModel(key: "decision" | "runtime" | "severity" | "eventType" | "attackType") {
  return computed({ get: () => query.value[key], set: (value: string) => updateQuery({ [key]: value, page: 1 }) });
}
const decisionFilter = queryModel("decision");
const runtimeFilter = queryModel("runtime");
const severityFilter = queryModel("severity");
const eventTypeFilter = queryModel("eventType");
const attackTypeFilter = queryModel("attackType");

watch(() => query.value.search, (value) => {
  if (route.name === "investigations" && value !== searchDraft.value) searchDraft.value = value;
}, { immediate: true });
watch(searchDraft, (value) => {
  window.clearTimeout(searchTimer);
  if (route.name !== "investigations") return;
  searchTimer = window.setTimeout(() => {
    if (route.name === "investigations") updateQuery({ search: value, page: 1 });
  }, 250);
});
onDeactivated(() => window.clearTimeout(searchTimer));
onUnmounted(() => window.clearTimeout(searchTimer));

function updateQuery(patch: Record<string, string | number | undefined>) {
  if (route.name !== "investigations") return;
  void router.replace({ path: "/investigations", query: mergeInvestigationQuery(route.query, patch) });
}
function handleSelectEvent(eventId: string) { updateQuery({ event_id: eventId }); }
function handleCloseEvent() { updateQuery({ event_id: undefined }); }
function handlePage(page: number) { updateQuery({ page }); }
function handleQuickFilter(patch: { blocked: string; rule: string }) { updateQuery({ ...patch, page: 1 }); }
function handleClearFilters() { searchDraft.value = ""; void router.replace({ path: "/investigations", query: query.value.eventId ? { event_id: query.value.eventId } : {} }); }
function handleExport() {
  const headers = ["时间", "决策", "严重性", "风险分", "运行时", "阶段", "事件类型", "工具", "资源", "原因", "证据链 ID", "Case ID", "规则命中"];
  const rows = filteredEvents.value.map((e) => [
    e.occurredAt, e.decision, e.severity, e.riskScore, e.runtime, e.stage,
    e.eventType, e.tool, e.resource, e.reason, e.traceId, e.caseId ?? "",
    formatRuleListForDisplay(e.ruleHits),
  ]);
  const csv = [headers, ...rows].map((row) =>
    row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(",")
  ).join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `audit-events-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click(); URL.revokeObjectURL(url);
}
</script>

<style scoped lang="scss">
.investigations-page { display: grid; grid-template-columns: minmax(0, 1fr); }
.investigations-page--detail { grid-template-columns: minmax(0, 1fr) minmax(22rem, 26rem); }
.investigations-page__main { min-width: 0; }
.investigation-tools { align-items: end; border-block: 1px solid var(--color-border); display: grid; gap: var(--space-3); grid-template-columns: minmax(16rem, 1fr) repeat(5, minmax(7rem, .4fr)) auto; padding: var(--space-4) 0; }
@media (max-width: 1280px) { .investigation-tools { grid-template-columns: 1fr repeat(3, minmax(7rem, .4fr)) auto; } .investigation-tools > :nth-child(5), .investigation-tools > :nth-child(6) { grid-column: auto; } }
@media (max-width: 1180px) { .investigation-tools { grid-template-columns: repeat(3, 1fr); } .investigation-search { grid-column: 1 / -1; } }
.page-header-actions { align-items: center; display: flex; gap: var(--space-3); }
.investigation-search { color: var(--color-text-muted); display: grid; font-size: var(--font-size-12); font-weight: var(--font-weight-semibold); gap: var(--space-1); }
.investigation-search input { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); min-height: 2.5rem; padding: 0 var(--space-3); width: 100%; }
.clear-filters { background: transparent; border: 0; color: var(--color-link); cursor: pointer; min-height: 2.5rem; }
.quick-filters { display: flex; flex-wrap: wrap; gap: var(--space-2); padding: var(--space-3) 0 var(--space-5); }
.quick-filters button { background: transparent; border: 1px solid var(--color-border); border-radius: var(--radius-pill); color: var(--color-text-muted); cursor: pointer; font-size: var(--font-size-12); max-width: 16rem; min-height: 2rem; overflow: hidden; padding: 0 var(--space-3); text-overflow: ellipsis; white-space: nowrap; }
.quick-filters button[aria-pressed="true"] { background: var(--color-active-soft); border-color: var(--color-active-border); color: var(--color-active); }
.result-summary { align-items: baseline; display: flex; gap: var(--space-2); padding-bottom: var(--space-2); }
.result-summary span { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.result-summary span:last-child { margin-left: auto; }
.event-table-wrap { overflow: auto; }
.event-table { border-collapse: collapse; min-width: 54rem; width: 100%; }
.event-table caption { height: 1px; overflow: hidden; position: absolute; width: 1px; }
.event-table th, .event-table td { border-bottom: 1px solid var(--color-border); font-size: var(--font-size-13); max-width: 18rem; padding: var(--space-3); text-align: left; vertical-align: middle; }
.event-table th { color: var(--color-text-subtle); font-size: var(--font-size-11); letter-spacing: .03em; text-transform: uppercase; }
.event-table tbody tr { cursor: pointer; }
.event-table tbody tr:hover, .event-table tbody tr:focus-visible, .event-table__selected { background: var(--color-row-hover); }
.event-table tbody tr:focus-visible { box-shadow: inset 0 0 0 2px var(--color-focus); outline: 0; }
.event-table__selected { box-shadow: inset 2px 0 var(--color-active); }
.event-time { color: var(--color-link); font-weight: var(--font-weight-semibold); }
.event-table td:nth-child(5) { display: grid; gap: var(--space-1); }
.event-risk { align-items: center; display: grid; gap: var(--space-2); grid-template-columns: minmax(2.5rem, 1fr) auto; }
.event-risk::before { background: var(--color-surface-muted); content: ""; grid-column: 1; grid-row: 1; height: .25rem; }
.event-risk i { background: var(--color-active); grid-column: 1; grid-row: 1; height: .25rem; max-width: 100%; }
.event-risk--critical i, .event-risk--high i { background: var(--color-danger); }
.event-risk--medium i { background: var(--color-warning); }
.pagination { align-items: center; color: var(--color-text-muted); display: flex; font-size: var(--font-size-12); justify-content: space-between; padding-top: var(--space-4); }
.pagination div { display: flex; gap: var(--space-2); }
.pagination button { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); min-height: 2.25rem; padding: 0 var(--space-3); }
.pagination button:disabled { opacity: .45; }
.trace-preview { border-top: 1px solid var(--color-border); display: grid; gap: var(--space-4); padding-top: var(--space-4); }
.trace-preview > header { align-items: start; display: flex; justify-content: space-between; }
.trace-preview h3 { margin: 0; }
.trace-preview header span { color: var(--color-text-subtle); font-size: var(--font-size-12); }
@media (max-width: 1180px) { .investigation-tools { grid-template-columns: repeat(3, 1fr); } .investigation-search { grid-column: 1 / -1; } }
@media (max-width: 900px) { .investigations-page, .investigations-page--detail { grid-template-columns: 1fr; } }
@media (max-width: 640px) {
  .investigation-tools { grid-template-columns: 1fr; }
  .investigation-search { grid-column: auto; }
  .event-table { min-width: 0; table-layout: fixed; width: 100%; }
  .event-table th, .event-table td { padding: var(--space-3) var(--space-2); }
  .event-table th:nth-child(1) { width: 4.25rem; }
  .event-table th:nth-child(2) { width: 4.75rem; }
  .event-table th:nth-child(3) { width: 4rem; }
  .event-table th:nth-child(4), .event-table td:nth-child(4),
  .event-table th:nth-child(6), .event-table td:nth-child(6) { display: none; }
  .event-table td:nth-child(5) code { display: block; overflow: hidden; text-overflow: ellipsis; }
  .event-risk { gap: var(--space-1); grid-template-columns: minmax(1rem, 1fr) auto; }
}
</style>
