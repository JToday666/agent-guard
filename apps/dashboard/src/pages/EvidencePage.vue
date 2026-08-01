<template>
  <section class="evidence-page workspace-panel" aria-labelledby="evidence-title">
    <header class="page-header">
      <div><h1 id="evidence-title">证据链</h1></div>
      <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
    </header>

    <form class="evidence-tools" role="search" @submit.prevent>
      <label>
        <span>搜索证据链</span>
        <span class="evidence-search">
          <Search aria-hidden="true" :size="15" />
          <input v-model.trim="searchText" placeholder="Trace ID、Case 或结论" type="search" />
        </span>
      </label>
      <AppSelect
        id="evidence-status"
        v-model="statusFilter"
        label="最终状态"
        :options="statusOptions"
      />
      <button v-if="hasFilters" class="evidence-clear" type="button" @click="handleClearFilters">
        清除筛选
      </button>
    </form>

    <ErrorState
      v-if="store.status === 'error' && store.error"
      :is-retrying="store.isRefreshing"
      :message="store.error"
      @retry="store.refresh"
    />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
    <template v-else-if="filteredTraces.length">
      <div class="evidence-summary">
        <strong>{{ filteredTraces.length }}</strong>
        <span>条匹配证据链</span>
        <span>一行代表一个 Trace · 按最新事件排序</span>
      </div>
      <div class="trace-table-wrap">
        <table class="trace-table">
          <caption>
            证据链列表
          </caption>
          <thead>
            <tr>
              <th>Case</th>
              <th>Trace 与最终结论</th>
              <th>事件</th>
              <th>最终状态</th>
              <th>最后事件</th>
              <th><span class="sr-only">操作</span></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="trace in filteredTraces" :key="trace.id">
              <td>
                <code>{{ trace.caseId }}</code>
              </td>
              <td>
                <RouterLink :to="`/evidence/${trace.id}`">{{ trace.title }}</RouterLink>
                <code>{{ trace.id }}</code>
              </td>
              <td class="trace-table__count">{{ traceEventCount(trace.id) }}</td>
              <td>
                <StatusBadge
                  :label="getTraceStatusLabel(trace.status)"
                  :tone="getTraceStatusTone(trace.status)"
                />
              </td>
              <td>
                <time>{{ formatDashboardDateTime(trace.lastEventAt) }}</time>
              </td>
              <td>
                <RouterLink class="trace-table__action" :to="`/evidence/${trace.id}`">
                  查看
                  <ArrowUpRight aria-hidden="true" :size="14" />
                </RouterLink>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
    <EmptyState
      v-else
      :title="store.traces.length ? '没有匹配证据链' : '暂无证据链'"
      :message="
        store.traces.length
          ? '当前条件下没有证据链，请调整搜索或最终状态。'
          : '审计事件写入后将在这里汇总同一任务的完整证据。'
      "
    />
  </section>
</template>

<script setup lang="ts">
import { ArrowUpRight, Search } from "@lucide/vue";
import { computed } from "vue";
import { useRoute, useRouter } from "vue-router";

import AppSelect from "../components/common/AppSelect.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useDashboardStore } from "../stores/dashboardStore";
import {
  formatDashboardDateTime,
  getTraceStatusLabel,
  getTraceStatusTone,
} from "../utils/dashboard-formatters";

defineOptions({ name: "EvidencePage" });

const store = useDashboardStore();
const route = useRoute();
const router = useRouter();
const searchText = computed({
  get: () => (typeof route.query.search === "string" ? route.query.search : ""),
  set: (value: string) => updateQuery({ search: value || undefined }),
});
const statusFilter = computed({
  get: () => (typeof route.query.status === "string" ? route.query.status : ""),
  set: (value: string) => updateQuery({ status: value || undefined }),
});
const statusOptions = [
  { label: "全部", value: "" },
  { label: "已阻断", value: "blocked" },
  { label: "待审批", value: "paused" },
  { label: "已放行", value: "allowed" },
];
const hasFilters = computed(() => Boolean(searchText.value || statusFilter.value));
const filteredTraces = computed(() => {
  const search = searchText.value.toLocaleLowerCase();
  return store.traces.filter(
    (trace) =>
      (!statusFilter.value || trace.status === statusFilter.value) &&
      (!search ||
        `${trace.id} ${trace.caseId} ${trace.title}`.toLocaleLowerCase().includes(search)),
  );
});

function traceEventCount(traceId: string): number {
  return store.investigationIndex.byTrace.get(traceId)?.length ?? 0;
}

function updateQuery(patch: Record<string, string | undefined>): void {
  void router.replace({
    path: "/evidence",
    query: { ...route.query, ...patch },
  });
}

function handleClearFilters(): void {
  void router.replace({ path: "/evidence" });
}
</script>

<style scoped lang="scss">
.evidence-page {
  display: grid;
  gap: var(--space-5);
}

.evidence-tools {
  align-items: end;
  border-block: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(18rem, 1fr) minmax(10rem, 13rem) auto;
  padding: var(--space-4) 0;
}

.evidence-clear {
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  min-height: 2.5rem;
  padding: 0 var(--space-3);
}

.evidence-clear:hover {
  background: var(--color-surface-muted);
  border-color: var(--color-active-border);
}

.evidence-tools > label {
  color: var(--color-text-muted);
  display: grid;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-1);
}

.evidence-search {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-text-subtle);
  display: flex;
  gap: var(--space-2);
  min-height: 2.5rem;
  padding: 0 var(--space-3);

  &:focus-within {
    border-color: var(--color-active-border);
    box-shadow: var(--glow-active);
  }

  input {
    background: transparent;
    border: 0;
    color: var(--color-text);
    min-width: 0;
    outline: 0;
    width: 100%;
  }
}

.evidence-summary {
  align-items: baseline;
  display: flex;
  gap: var(--space-2);
}

.evidence-summary span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}

.evidence-summary span:last-child {
  margin-left: auto;
}

.trace-table-wrap {
  border-top: 1px solid var(--color-border-strong);
  overflow-x: auto;
}

.trace-table {
  border-collapse: collapse;
  min-width: 58rem;
  width: 100%;
}

.trace-table caption {
  height: 1px;
  overflow: hidden;
  position: absolute;
  width: 1px;
}

.trace-table th,
.trace-table td {
  border-bottom: 1px solid var(--color-border);
  font-size: var(--font-size-13);
  padding: var(--space-3);
  text-align: left;
  vertical-align: middle;
}

.trace-table th {
  background: color-mix(in srgb, var(--color-page) 92%, var(--color-surface));
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  letter-spacing: 0.04em;
}

.trace-table tbody tr:hover {
  background: var(--color-row-hover);
}

.trace-table td:nth-child(1) {
  max-width: 9rem;
}

.trace-table td:nth-child(2) {
  display: grid;
  gap: var(--space-1);
  min-width: 17rem;
}

.trace-table td:nth-child(2) > a {
  color: var(--color-text);
  font-weight: var(--font-weight-semibold);
  overflow: hidden;
  text-decoration: none;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.trace-table td:nth-child(2) > a:hover {
  color: var(--color-link);
  text-decoration: underline;
}

.trace-table td:nth-child(2) code,
.trace-table time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.trace-table__count {
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-semibold);
}

.trace-table__action {
  align-items: center;
  color: var(--color-link);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-1);
  text-decoration: none;
}
</style>
