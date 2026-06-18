<template>
  <div class="events-page page-with-drawer" :class="{ 'events-page--drawer-open': Boolean(selectedEventId) }">
    <section class="workspace-panel events-page__main" aria-labelledby="events-title">
      <header class="page-header">
        <div>
          <p>监控</p>
          <h1 id="events-title">事件</h1>
        </div>
        <StatusBadge label="部分数据" tone="neutral" />
      </header>

      <form class="filter-bar" @submit.prevent>
        <AppSelect id="events-decision-filter" v-model="decisionFilter" label="决策" :options="decisionOptions" />
        <AppSelect id="events-runtime-filter" v-model="runtimeFilter" label="运行时" :options="runtimeOptions" />
        <label>
          搜索
          <input v-model.trim="searchFilter" type="search" placeholder="资源 / 规则 / 原因" />
        </label>
      </form>

      <div class="quick-filters" aria-label="快速筛选">
        <button
          v-for="filter in quickFilters"
          :key="filter.key"
          type="button"
          :aria-pressed="isQuickFilterActive(filter.key)"
          :class="{ 'quick-filters__button--active': isQuickFilterActive(filter.key) }"
          @click="handleQuickFilterClick(filter.key)"
        >
          {{ filter.label }} {{ filter.count }}
        </button>
      </div>

      <div v-if="filteredEvents.length > 0" class="table-wrap">
        <table class="audit-table">
          <caption>
            审计事件
          </caption>
          <thead>
            <tr>
              <th scope="col">时间</th>
              <th scope="col">决策</th>
              <th scope="col">风险</th>
              <th scope="col">严重性</th>
              <th scope="col">阻断</th>
              <th scope="col">运行时</th>
              <th scope="col">工具</th>
              <th scope="col">资源</th>
              <th scope="col">原因</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="event in filteredEvents"
              :key="event.id"
              :class="{ 'audit-table__row--selected': selectedEvent?.id === event.id }"
              tabindex="0"
              @click="handleSelectEvent(event)"
              @keydown.enter.prevent="handleSelectEvent(event)"
              @keydown.space.prevent="handleSelectEvent(event)"
            >
              <td>
                <span class="table-link">{{ event.time }}</span>
              </td>
              <td>
                <StatusBadge :label="getDecisionLabel(event.decision)" :tone="getDecisionTone(event.decision)" />
              </td>
              <td>
                <span class="risk-score">{{ event.riskScore }}</span>
              </td>
              <td>
                <StatusBadge :label="getSeverityLabel(event.severity)" :tone="getSeverityTone(event.severity)" />
              </td>
              <td>{{ event.blocked ? "是" : "否" }}</td>
              <td>{{ event.runtime }}</td>
              <td>
                <code>{{ event.tool }}</code>
              </td>
              <td>
                <span class="truncate-cell" :title="event.resource">{{ event.resource }}</span>
              </td>
              <td>
                <span class="truncate-cell" :title="event.reason">{{ event.reason }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <EmptyState
        v-else
        message="当前筛选条件下没有事件。调整筛选后可继续查看审计记录。"
        title="暂无事件"
      />
    </section>

    <DetailDrawer
      :is-open="Boolean(selectedEventId)"
      eyebrow="事件详情"
      :title="selectedEvent?.id ?? '未找到事件'"
      @close="handleCloseDrawer"
    >
      <template v-if="selectedEvent">
        <section class="detail-section">
          <h2>风险摘要</h2>
          <dl>
            <div>
              <dt>决策</dt>
              <dd>{{ getDecisionLabel(selectedEvent.decision) }}</dd>
            </div>
            <div>
              <dt>风险分数</dt>
              <dd>{{ selectedEvent.riskScore }}</dd>
            </div>
            <div>
              <dt>严重性</dt>
              <dd>{{ getSeverityLabel(selectedEvent.severity) }}</dd>
            </div>
            <div>
              <dt>已阻断</dt>
              <dd>{{ selectedEvent.blocked ? "true" : "false" }}</dd>
            </div>
          </dl>
        </section>

        <section class="detail-section">
          <h2>任务与行为</h2>
          <p><strong>用户任务:</strong> {{ selectedEvent.userTask }}</p>
          <p><strong>Agent 行为:</strong> {{ selectedEvent.agentAction }}</p>
          <p><strong>原因:</strong> {{ selectedEvent.reason }}</p>
        </section>

        <section class="detail-section detail-section__links">
          <h2>关联信息</h2>
          <RouterLink :to="`/traces/${selectedEvent.traceId}`">{{ selectedEvent.traceId }}</RouterLink>
          <RouterLink :to="`/evaluation?case_id=${selectedEvent.caseId}`">{{ selectedEvent.caseId }}</RouterLink>
          <RouterLink v-if="selectedEvent.approvalId" :to="`/approvals/${selectedEvent.approvalId}`">
            {{ selectedEvent.approvalId }}
          </RouterLink>
        </section>

        <section class="detail-section">
          <h2>命中规则</h2>
          <div class="tag-list">
            <span v-for="rule in selectedEvent.ruleHits" :key="rule">{{ rule }}</span>
            <span v-if="selectedEvent.ruleHits.length === 0">未命中阻断规则</span>
          </div>
        </section>

        <section class="detail-section">
          <h2>原始 JSON</h2>
          <pre>{{ selectedEvent }}</pre>
        </section>
      </template>
      <EmptyState
        v-else
        message="当前事件不存在或已不在筛选范围内。关闭详情后可继续查看事件列表。"
        title="未找到事件"
      />
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRoute, useRouter, type LocationQueryRaw } from "vue-router";

import AppSelect from "../components/AppSelect.vue";
import DetailDrawer from "../components/DetailDrawer.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { auditEvents } from "../mocks/dashboard-data";
import type { AuditEventRow, DecisionStatus, RiskSeverity } from "../types/dashboard";

defineOptions({
  name: "EventsPage",
});

const route = useRoute();
const router = useRouter();

const decisionFilter = computed({
  get: () => getQueryString("decision"),
  set: (value: string) => updateEventQuery({ decision: value, rule: undefined }),
});
const runtimeFilter = computed({
  get: () => getQueryString("runtime"),
  set: (value: string) => updateEventQuery({ runtime: value }),
});
const searchFilter = computed({
  get: () => getQueryString("search"),
  set: (value: string) => updateEventQuery({ search: value }),
});
const decisionOptions = [
  { label: "全部", value: "" },
  { label: "拒绝", value: "deny" },
  { label: "待确认", value: "ask" },
  { label: "放行", value: "allow" },
];
const runtimeOptions = [
  { label: "全部", value: "" },
  { label: "LangGraph", value: "langgraph" },
  { label: "OpenClaw", value: "openclaw" },
];

const decisionQuickFilters = [
  { decision: "deny", label: "拒绝" },
  { decision: "ask", label: "待确认" },
] as const;
const ruleQuickFilters = [
  { label: "敏感文件", rule: "P001_sensitive_file_access" },
  { label: "外部发送", rule: "P005_external_send" },
  { label: "任务不一致", rule: "P004_task_mismatch" },
] as const;

type QuickFilterKey = "all" | `decision:${DecisionStatus}` | `rule:${string}`;

const latestEvents = computed(() =>
  [...auditEvents].sort((left, right) => Date.parse(right.occurredAt) - Date.parse(left.occurredAt)),
);
const selectedEventId = computed(() => getQueryString("event_id"));
const selectedEvent = computed(() =>
  selectedEventId.value ? latestEvents.value.find((event) => event.id === selectedEventId.value) : undefined,
);
const ruleFilter = computed(() => getQueryString("rule"));
const quickFilters = computed<Array<{ count: number; key: QuickFilterKey; label: string }>>(() => [
  { count: latestEvents.value.length, key: "all", label: "全部" },
  ...decisionQuickFilters.map((filter) => ({
    count: getDecisionCount(filter.decision),
    key: `decision:${filter.decision}` as const,
    label: filter.label,
  })),
  ...ruleQuickFilters.map((filter) => ({
    count: getRuleHitCount(filter.rule),
    key: `rule:${filter.rule}` as const,
    label: filter.label,
  })),
]);

const filteredEvents = computed(() =>
  latestEvents.value.filter((event) => {
    const searchValue = searchFilter.value.toLowerCase();
    const ruleValue = ruleFilter.value;
    const severityValue = getQueryString("severity");
    const blockedValue = getQueryString("blocked");
    const typeValue = getQueryString("type").toLowerCase();
    const matchesDecision = !decisionFilter.value || event.decision === decisionFilter.value;
    const matchesRuntime = !runtimeFilter.value || event.runtime === runtimeFilter.value;
    const matchesRule = !ruleValue || event.ruleHits.includes(ruleValue);
    const matchesSeverity = !severityValue || event.severity === severityValue;
    const matchesBlocked =
      !blockedValue ||
      (blockedValue === "true" && event.blocked) ||
      (blockedValue === "false" && !event.blocked);
    const searchableText = [
      event.resource,
      event.reason,
      event.tool,
      event.caseId,
      event.traceId,
      event.stage,
      ...event.ruleHits,
    ]
      .join(" ")
      .toLowerCase();
    const matchesType = !typeValue || searchableText.includes(typeValue);
    const matchesSearch =
      !searchValue || searchableText.includes(searchValue);

    return (
      matchesDecision &&
      matchesRuntime &&
      matchesRule &&
      matchesSeverity &&
      matchesBlocked &&
      matchesType &&
      matchesSearch
    );
  }),
);

function handleSelectEvent(event: AuditEventRow): void {
  updateEventQuery({ event_id: event.id });
}

function handleCloseDrawer(): void {
  updateEventQuery({ event_id: undefined });
}

function handleQuickFilterClick(key: QuickFilterKey): void {
  if (key === "all") {
    updateEventQuery({ decision: undefined, rule: undefined });
    return;
  }

  if (key.startsWith("decision:")) {
    updateEventQuery({ decision: key.replace("decision:", ""), rule: undefined });
    return;
  }

  updateEventQuery({ decision: undefined, rule: key.replace("rule:", "") });
}

function isQuickFilterActive(key: QuickFilterKey): boolean {
  if (key === "all") return !decisionFilter.value && !ruleFilter.value;
  if (key.startsWith("decision:")) {
    return decisionFilter.value === key.replace("decision:", "") && !ruleFilter.value;
  }
  return ruleFilter.value === key.replace("rule:", "") && !decisionFilter.value;
}

function getDecisionCount(decision: DecisionStatus): number {
  return latestEvents.value.filter((event) => event.decision === decision).length;
}

function getRuleHitCount(rule: string): number {
  return latestEvents.value.filter((event) => event.ruleHits.includes(rule)).length;
}

function getQueryString(key: string): string {
  const value = route.query[key];
  return typeof value === "string" ? value : "";
}

function updateEventQuery(nextQuery: Record<string, string | undefined>): void {
  const query: LocationQueryRaw = { ...route.query };

  Object.entries(nextQuery).forEach(([key, value]) => {
    const normalizedValue = typeof value === "string" ? value.trim() : value;
    if (normalizedValue) {
      query[key] = normalizedValue;
    } else {
      delete query[key];
    }
  });

  void router.replace({ path: "/events", query });
}

function getDecisionTone(decision: DecisionStatus): "neutral" | "success" | "warning" | "danger" {
  if (decision === "deny") return "danger";
  if (decision === "ask") return "warning";
  return "success";
}

function getDecisionLabel(decision: DecisionStatus): string {
  if (decision === "deny") return "拒绝";
  if (decision === "ask") return "待确认";
  return "放行";
}

function getSeverityTone(severity: RiskSeverity): "neutral" | "success" | "warning" | "danger" {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  return "success";
}

function getSeverityLabel(severity: RiskSeverity): string {
  if (severity === "critical") return "严重";
  if (severity === "high") return "高";
  if (severity === "medium") return "中";
  return "低";
}
</script>

<style scoped lang="scss">
.events-page {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
}

.events-page--drawer-open {
  grid-template-columns: minmax(0, 1fr) minmax(20rem, 24rem);
}

.events-page__main {
  min-width: 0;
}

.filter-bar {
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(8rem, 12rem) minmax(8rem, 12rem) minmax(14rem, 1fr);
  margin-bottom: var(--space-4);

  label {
    color: var(--color-text-muted);
    display: grid;
    font-size: var(--font-size-12);
    font-weight: var(--font-weight-semibold);
    gap: var(--space-1);
  }

  input {
    background:
      linear-gradient(180deg, rgb(255 255 255 / 0.98), rgb(246 249 253 / 0.96));
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    box-shadow: var(--shadow-subtle);
    color: var(--color-text);
    min-height: 2.5rem;
    padding: 0 var(--space-3);
    width: 100%;

    &::placeholder {
      color: var(--color-text-subtle);
    }

    &:hover {
      border-color: var(--color-active-border);
      box-shadow: 0 8px 18px rgb(37 99 235 / 0.08);
    }
  }
}

.quick-filters {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin-bottom: var(--space-4);

  button {
    align-items: center;
    background: var(--color-surface-muted);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    color: var(--color-text-muted);
    cursor: pointer;
    display: inline-flex;
    font-size: var(--font-size-12);
    font-weight: var(--font-weight-semibold);
    gap: var(--space-2);
    min-height: 2rem;
    padding: 0 var(--space-3);

    &:hover {
      background: var(--color-active-soft);
      border-color: var(--color-active-border);
      color: var(--color-active);
    }
  }
}

.quick-filters__button--active {
  background: var(--color-active) !important;
  border-color: var(--color-active) !important;
  box-shadow: var(--shadow-subtle);
  color: var(--color-active-text) !important;

  &::before {
    content: "";
    background: currentColor;
    border-radius: 999px;
    height: 0.375rem;
    width: 0.375rem;
  }
}

.table-wrap {
  overflow: auto;
}

.audit-table {
  border-collapse: collapse;
  min-width: 58rem;
  width: 100%;

  caption {
    height: 1px;
    overflow: hidden;
    position: absolute;
    white-space: nowrap;
    width: 1px;
  }

  th,
  td {
    border-bottom: 1px solid var(--color-border);
    font-size: var(--font-size-13);
    line-height: var(--line-height-ui);
    max-width: 14rem;
    padding: var(--space-3);
    text-align: left;
    vertical-align: middle;
  }

  th {
    color: var(--color-text-subtle);
    font-size: var(--font-size-12);
    font-weight: var(--font-weight-bold);
  }

  tbody tr {
    cursor: pointer;
    transition:
      background-color var(--transition-fast),
      box-shadow var(--transition-fast);

    &:hover {
      background: var(--color-row-hover);
    }

    &:focus-visible {
      box-shadow: inset 0 0 0 2px var(--color-focus);
      outline: 0;
    }
  }
}

.audit-table__row--selected {
  background: var(--color-active-soft);
  box-shadow: inset 3px 0 0 var(--color-active);
}

.table-link {
  color: var(--color-link);
  font: inherit;
  font-weight: var(--font-weight-semibold);
}

.risk-score {
  font-weight: var(--font-weight-bold);
}

.detail-section {
  display: grid;
  gap: var(--space-2);

  h2 {
    font-size: var(--font-size-14);
    font-weight: var(--font-weight-bold);
    margin: 0;
  }

  p {
    margin: 0;
    overflow-wrap: anywhere;
  }

  dl {
    display: grid;
    gap: var(--space-2);
    margin: 0;
  }

  dl > div {
    display: flex;
    gap: var(--space-3);
    justify-content: space-between;
  }

  dt {
    color: var(--color-text-subtle);
  }

  dd {
    font-weight: var(--font-weight-semibold);
    margin: 0;
    overflow-wrap: anywhere;
    text-align: right;
  }

  pre {
    background: var(--color-surface-muted);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    margin: 0;
    max-height: 16rem;
    overflow: auto;
    padding: var(--space-3);
    white-space: pre-wrap;
  }
}

.detail-section__links,
.tag-list {
  align-items: start;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);

  a,
  span {
    background: var(--color-surface-muted);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    color: var(--color-text);
    font-size: var(--font-size-12);
    max-width: 100%;
    overflow: hidden;
    padding: var(--space-2) var(--space-3);
    text-overflow: ellipsis;
    text-decoration: none;
    white-space: nowrap;
  }
}

@media (max-width: 1100px) {
  .events-page {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (max-width: 640px) {
  .filter-bar {
    grid-template-columns: 1fr;
  }

  .audit-table {
    min-width: 36rem;

    th:nth-child(3),
    td:nth-child(3),
    th:nth-child(4),
    td:nth-child(4),
    th:nth-child(5),
    td:nth-child(5),
    th:nth-child(6),
    td:nth-child(6) {
      display: none;
    }
  }
}
</style>
