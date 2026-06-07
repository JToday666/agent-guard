<template>
  <div class="events-page page-with-drawer">
    <section class="workspace-panel events-page__main" aria-labelledby="events-title">
      <header class="page-header">
        <div>
          <p>监控</p>
          <h1 id="events-title">事件</h1>
        </div>
        <StatusBadge label="部分数据" tone="neutral" />
      </header>

      <form class="filter-bar" @submit.prevent>
        <label>
          决策
          <select v-model="decisionFilter">
            <option value="">全部</option>
            <option value="deny">拒绝</option>
            <option value="ask">待确认</option>
            <option value="allow">放行</option>
          </select>
        </label>
        <label>
          运行时
          <select v-model="runtimeFilter">
            <option value="">全部</option>
            <option value="langgraph">LangGraph</option>
            <option value="openclaw">OpenClaw</option>
          </select>
        </label>
        <label>
          搜索
          <input v-model.trim="searchFilter" type="search" placeholder="资源 / 规则 / 原因" />
        </label>
      </form>

      <div class="quick-filters" aria-label="快速筛选">
        <button type="button" @click="decisionFilter = 'deny'">拒绝 {{ denyCount }}</button>
        <button type="button" @click="decisionFilter = 'ask'">待确认 {{ askCount }}</button>
        <button type="button" @click="searchFilter = 'sensitive'">敏感文件</button>
        <button type="button" @click="searchFilter = 'external'">外部发送</button>
        <button type="button" @click="searchFilter = 'mismatch'">任务不一致</button>
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
            >
              <td>
                <button class="table-link" type="button" @click="handleSelectEvent(event)">
                  {{ event.time }}
                </button>
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
      :is-open="Boolean(selectedEvent)"
      eyebrow="事件详情"
      :title="selectedEvent?.id ?? ''"
      @close="selectedEvent = undefined"
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
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useRoute } from "vue-router";

import DetailDrawer from "../components/DetailDrawer.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { auditEvents } from "../mocks/dashboard-data";
import type { AuditEventRow, DecisionStatus, RiskSeverity } from "../types/dashboard";

defineOptions({
  name: "EventsPage",
});

const route = useRoute();
const selectedEvent = ref<AuditEventRow | undefined>();
const decisionFilter = ref("");
const runtimeFilter = ref("");
const searchFilter = ref("");

const denyCount = computed(() => auditEvents.filter((event) => event.decision === "deny").length);
const askCount = computed(() => auditEvents.filter((event) => event.decision === "ask").length);
const latestEvents = computed(() =>
  [...auditEvents].sort((left, right) => Date.parse(right.occurredAt) - Date.parse(left.occurredAt)),
);

const filteredEvents = computed(() =>
  latestEvents.value.filter((event) => {
    const searchValue = searchFilter.value.toLowerCase();
    const matchesDecision = !decisionFilter.value || event.decision === decisionFilter.value;
    const matchesRuntime = !runtimeFilter.value || event.runtime === runtimeFilter.value;
    const matchesSearch =
      !searchValue ||
      [event.resource, event.reason, event.tool, event.caseId, event.traceId, ...event.ruleHits]
        .join(" ")
        .toLowerCase()
        .includes(searchValue);

    return matchesDecision && matchesRuntime && matchesSearch;
  }),
);

watch(
  () => route.query,
  (query) => {
    decisionFilter.value = typeof query.decision === "string" ? query.decision : "";
    runtimeFilter.value = typeof query.runtime === "string" ? query.runtime : "";
    searchFilter.value =
      typeof query.search === "string"
        ? query.search
        : typeof query.event_id === "string"
          ? query.event_id
          : "";
    selectedEvent.value =
      typeof query.event_id === "string"
        ? latestEvents.value.find((event) => event.id === query.event_id)
        : selectedEvent.value;
  },
  { immediate: true },
);

function handleSelectEvent(event: AuditEventRow): void {
  selectedEvent.value = event;
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
    font-weight: 700;
    gap: var(--space-1);
  }

  input,
  select {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    color: var(--color-text);
    min-height: 2.375rem;
    padding: 0 var(--space-3);
  }
}

.quick-filters {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin-bottom: var(--space-4);

  button {
    background: var(--color-surface-muted);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    color: var(--color-text-muted);
    cursor: pointer;
    font-size: var(--font-size-12);
    font-weight: 700;
    min-height: 2rem;
    padding: 0 var(--space-3);
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
    max-width: 14rem;
    padding: var(--space-3);
    text-align: left;
    vertical-align: middle;
  }

  th {
    color: var(--color-text-subtle);
    font-size: var(--font-size-12);
    font-weight: 760;
  }
}

.audit-table__row--selected {
  background: var(--color-active-soft);
}

.table-link {
  background: transparent;
  border: 0;
  color: var(--color-link);
  cursor: pointer;
  font: inherit;
  padding: 0;
}

.risk-score {
  font-weight: 760;
}

.detail-section {
  display: grid;
  gap: var(--space-2);

  h2 {
    font-size: var(--font-size-14);
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
    font-weight: 700;
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
