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
          <input
            v-model.trim="searchDraft"
            autocomplete="off"
            name="trace-search"
            placeholder="证据链 ID、评测样本或结论…"
            type="search"
          />
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
      :is-retrying="store.isManualRefreshing"
      :message="store.error"
      @retry="store.refresh"
    />
    <LoadingState v-else-if="store.status === 'loading' && !store.events.length" />
    <template v-else-if="filteredTraces.length">
      <div class="evidence-summary">
        <strong>{{ filteredTraces.length }}</strong>
        <span>条匹配证据链</span>
        <span>基于最近加载的最多 {{ AUDIT_EVENT_WINDOW_LIMIT }} 条审计事件 · 按最新事件排序</span>
      </div>
      <div class="trace-table-wrap">
        <table class="trace-table">
          <caption>
            证据链列表
          </caption>
          <thead>
            <tr>
              <th>评测样本</th>
              <th>证据链与结论</th>
              <th>事件</th>
              <th>最终状态</th>
              <th>最后事件</th>
              <th><span class="sr-only">操作</span></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="trace in paginatedTraces" :key="trace.id">
              <td>
                <code>{{ trace.caseId }}</code>
              </td>
              <td>
                <strong class="trace-table__title">{{ trace.title }}</strong>
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
                <time :datetime="trace.lastEventAt">{{
                  formatDashboardDateTime(trace.lastEventAt)
                }}</time>
              </td>
              <td>
                <RouterLink class="trace-table__action" :to="`/evidence/${trace.id}`">
                  查看详情
                  <ArrowUpRight aria-hidden="true" :size="14" />
                </RouterLink>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <footer v-if="totalPages > 1" class="evidence-pagination" aria-label="证据链分页">
        <span>第 {{ currentPage }} / {{ totalPages }} 页</span>
        <div>
          <button type="button" :disabled="currentPage === 1" @click="handlePage(currentPage - 1)">
            上一页
          </button>
          <button
            type="button"
            :disabled="currentPage === totalPages"
            @click="handlePage(currentPage + 1)"
          >
            下一页
          </button>
        </div>
      </footer>
    </template>
    <EmptyState
      v-else
      :title="store.traces.length ? '没有匹配证据链' : '暂无证据链'"
      :message="
        store.traces.length
          ? '当前条件下没有证据链，请调整搜索或最终状态。'
          : '审计事件写入后，这里会按证据链汇总展示。'
      "
    />
  </section>
</template>

<script setup lang="ts">
import { ArrowUpRight, Search } from "@lucide/vue";
import { computed, onDeactivated, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import AppSelect from "../components/common/AppSelect.vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { AUDIT_EVENT_WINDOW_LIMIT } from "../data/sources/dashboard-data-source";
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
const PAGE_SIZE = 20;
const searchDraft = ref("");
let searchTimer: number | undefined;
const searchText = computed(() =>
  typeof route.query.search === "string" ? route.query.search : "",
);
const statusFilter = computed({
  get: () => (typeof route.query.status === "string" ? route.query.status : ""),
  set: (value: string) => updateQuery({ status: value || undefined, page: undefined }),
});
const statusOptions = [
  { label: "全部", value: "" },
  { label: "拒绝", value: "denied" },
  { label: "需审批", value: "paused" },
  { label: "允许", value: "allowed" },
  { label: "未记录", value: "unknown" },
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
const requestedPage = computed(() => {
  const page = Number.parseInt(typeof route.query.page === "string" ? route.query.page : "1", 10);
  return Number.isFinite(page) && page > 0 ? page : 1;
});
const totalPages = computed(() => Math.max(1, Math.ceil(filteredTraces.value.length / PAGE_SIZE)));
const currentPage = computed(() => Math.min(requestedPage.value, totalPages.value));
const paginatedTraces = computed(() =>
  filteredTraces.value.slice((currentPage.value - 1) * PAGE_SIZE, currentPage.value * PAGE_SIZE),
);

watch(
  () => route.query.search,
  (value) => {
    if (route.name !== "evidence") return;
    const search = typeof value === "string" ? value : "";
    if (search !== searchDraft.value) searchDraft.value = search;
  },
  { immediate: true },
);
watch(searchDraft, (value) => {
  window.clearTimeout(searchTimer);
  if (route.name !== "evidence") return;
  searchTimer = window.setTimeout(() => {
    if (route.name === "evidence") {
      updateQuery({ search: value || undefined, page: undefined });
    }
  }, 250);
});
function clearSearchTimer() {
  window.clearTimeout(searchTimer);
}
onDeactivated(clearSearchTimer);
onUnmounted(clearSearchTimer);

function traceEventCount(traceId: string): number {
  return store.investigationIndex.byTrace.get(traceId)?.length ?? 0;
}

function updateQuery(patch: Record<string, string | number | undefined>): void {
  const query = { ...route.query, ...patch };
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === "") delete query[key];
  }
  void router.replace({
    path: "/evidence",
    query,
  });
}

function handlePage(page: number): void {
  updateQuery({ page: page > 1 ? page : undefined });
}

function handleClearFilters(): void {
  searchDraft.value = "";
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

.trace-table__title {
  color: var(--color-text);
  font-weight: var(--font-weight-semibold);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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
  border: 1px solid transparent;
  border-radius: var(--radius-2);
  color: var(--color-link);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-1);
  min-height: 2.25rem;
  padding: 0 var(--space-2);
  text-decoration: none;
}

.trace-table__action:hover {
  background: var(--color-surface-muted);
  border-color: var(--color-active-border);
}

.evidence-pagination {
  align-items: center;
  color: var(--color-text-muted);
  display: flex;
  font-size: var(--font-size-12);
  justify-content: space-between;
}

.evidence-pagination div {
  display: flex;
  gap: var(--space-2);
}

.evidence-pagination button {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  cursor: pointer;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}

.evidence-pagination button:disabled {
  cursor: default;
  opacity: 0.45;
}
</style>
