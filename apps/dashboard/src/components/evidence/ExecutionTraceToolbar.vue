<template>
  <div class="execution-toolbar">
    <div class="execution-toolbar__search">
      <label class="sr-only" for="execution-step-search">搜索运行步骤</label>
      <Search :size="15" aria-hidden="true" />
      <input
        id="execution-step-search"
        :value="searchQuery"
        autocomplete="off"
        name="execution-step-search"
        spellcheck="false"
        type="search"
        placeholder="搜索步骤、工具或资源…"
        @input="handleSearchInput"
      />
      <button
        v-if="searchQuery"
        type="button"
        aria-label="清除运行步骤搜索"
        title="清除搜索"
        @click="emit('update:search-query', '')"
      >
        <X :size="14" aria-hidden="true" />
      </button>
    </div>

    <div class="execution-toolbar__filters" aria-label="运行步骤筛选">
      <button
        v-for="option in filterOptions"
        :key="option.id"
        type="button"
        :aria-pressed="activeFilter === option.id"
        @click="emit('update:active-filter', option.id)"
      >
        {{ option.label }}
        <span>{{ option.count }}</span>
      </button>
    </div>

    <div class="execution-toolbar__layout" aria-label="执行轨迹布局">
      <button
        type="button"
        :aria-pressed="layout === 'graph'"
        title="图形视图"
        @click="emit('update:layout', 'graph')"
      >
        <Workflow :size="15" aria-hidden="true" />
        图形
      </button>
      <button
        type="button"
        :aria-pressed="layout === 'list'"
        title="列表视图"
        @click="emit('update:layout', 'list')"
      >
        <List :size="15" aria-hidden="true" />
        列表
      </button>
    </div>

    <span class="execution-toolbar__result-count" role="status">
      匹配 {{ resultCount }} / {{ totalCount }} 个步骤
    </span>
  </div>
</template>

<script setup lang="ts">
import { List, Search, Workflow, X } from "@lucide/vue";

import type {
  ExecutionStepFilter,
  ExecutionTraceLayout,
} from "../../data/evidence/execution-flow-layout";

defineOptions({ name: "ExecutionTraceToolbar" });

defineProps<{
  activeFilter: ExecutionStepFilter;
  filterOptions: ReadonlyArray<{
    count: number;
    id: ExecutionStepFilter;
    label: string;
  }>;
  layout: ExecutionTraceLayout;
  resultCount: number;
  searchQuery: string;
  totalCount: number;
}>();

const emit = defineEmits<{
  "update:active-filter": [filter: ExecutionStepFilter];
  "update:layout": [layout: ExecutionTraceLayout];
  "update:search-query": [query: string];
}>();

function handleSearchInput(event: Event): void {
  emit("update:search-query", (event.target as HTMLInputElement).value.trimStart());
}
</script>

<style scoped lang="scss">
.execution-toolbar {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}

.execution-toolbar__search {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  display: flex;
  flex: 1 1 17rem;
  min-height: 2.375rem;
  min-width: 0;
  padding-left: var(--space-3);
}

.execution-toolbar__search:focus-within {
  border-color: var(--color-focus);
  box-shadow: var(--shadow-focus);
}

.execution-toolbar__search > svg {
  color: var(--color-text-subtle);
  flex: 0 0 auto;
}

.execution-toolbar__search input {
  background: transparent;
  border: 0;
  color: var(--color-text);
  flex: 1;
  min-height: 2.375rem;
  min-width: 0;
  outline: 0;
  padding: 0 var(--space-2);
}

.execution-toolbar__search > button {
  align-items: center;
  background: transparent;
  border: 0;
  color: var(--color-text-subtle);
  display: inline-flex;
  height: 2.375rem;
  justify-content: center;
  width: 2.375rem;
}

.execution-toolbar__filters,
.execution-toolbar__layout {
  display: flex;
  gap: var(--space-1);
}

.execution-toolbar__filters button,
.execution-toolbar__layout button {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-link);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-2);
  justify-content: center;
  min-height: 2.375rem;
  padding: 0 var(--space-3);
}

.execution-toolbar__filters button[aria-pressed="true"],
.execution-toolbar__layout button[aria-pressed="true"] {
  background: var(--color-active-soft);
  border-color: var(--color-active-border);
  color: var(--color-active-strong);
}

.execution-toolbar__filters button span {
  color: var(--color-text-subtle);
  font-variant-numeric: tabular-nums;
}

.execution-toolbar__layout {
  border-left: 1px solid var(--color-border);
  padding-left: var(--space-3);
}

.execution-toolbar__result-count {
  color: var(--color-text-subtle);
  flex: 0 0 auto;
  font-size: var(--font-size-11);
  margin-left: auto;
}

@media (max-width: 72rem) {
  .execution-toolbar__result-count {
    margin-left: 0;
    width: 100%;
  }
}
</style>
