<template>
  <header class="top-bar">
    <div class="top-bar__brand">
      <RouterLink class="top-bar__title" to="/events">AgentGuard</RouterLink>
      <span class="top-bar__subtitle">运行时安全</span>
    </div>

    <div class="top-bar__status" aria-label="全局状态">
      <RouterLink class="top-bar__status-link" to="/system">
        <StatusBadge label="核心在线" tone="success" />
      </RouterLink>
      <button class="top-bar__chip" type="button" @click="handleRuntimeClick">
        运行时 LangGraph
      </button>
      <StatusBadge label="模式 enforce" tone="warning" />
      <span class="top-bar__chip">最近 24 小时</span>
    </div>

    <form class="top-bar__search" role="search" @submit.prevent="handleSearch">
      <label class="sr-only" for="global-search">搜索 Trace、Case、资源或规则</label>
      <input
        id="global-search"
        v-model.trim="searchText"
        name="search"
        placeholder="搜索 Trace / Case / 资源 / 规则"
        type="search"
      />
    </form>

    <RouterLink class="top-bar__pending" to="/approvals">
      待审批
      <strong>{{ pendingCount }}</strong>
    </RouterLink>
  </header>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";

import { getPendingApprovalCount } from "../mocks/dashboard-data";
import StatusBadge from "./StatusBadge.vue";

defineOptions({
  name: "AppTopBar",
});

const router = useRouter();
const searchText = ref("");
const pendingCount = getPendingApprovalCount();

function handleSearch(): void {
  void router.push({ path: "/events", query: searchText.value ? { search: searchText.value } : {} });
}

function handleRuntimeClick(): void {
  void router.push({ path: "/events", query: { runtime: "langgraph" } });
}
</script>

<style scoped lang="scss">
.top-bar {
  align-items: center;
  background: var(--color-surface);
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(10rem, 16rem) minmax(20rem, 1fr) minmax(16rem, 24rem) auto;
  min-height: var(--top-bar-height);
  padding: var(--space-3) var(--space-5);
  position: sticky;
  top: 0;
  z-index: 20;
}

.top-bar__brand,
.top-bar__status {
  min-width: 0;
}

.top-bar__title {
  color: var(--color-text);
  display: block;
  font-size: var(--font-size-18);
  font-weight: 760;
  text-decoration: none;
}

.top-bar__subtitle {
  color: var(--color-text-subtle);
  display: block;
  font-size: var(--font-size-12);
  margin-top: var(--space-1);
}

.top-bar__status {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.top-bar__status-link {
  color: inherit;
  text-decoration: none;
}

.top-bar__chip,
.top-bar__pending {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-pill);
  color: var(--color-text-muted);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: 650;
  gap: var(--space-2);
  min-height: 1.75rem;
  padding: 0 var(--space-3);
  text-decoration: none;
  white-space: nowrap;
}

button.top-bar__chip {
  cursor: pointer;
}

.top-bar__search {
  min-width: 0;

  input {
    background: var(--color-surface-muted);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    color: var(--color-text);
    min-height: 2.25rem;
    padding: 0 var(--space-3);
    width: 100%;
  }
}

.top-bar__pending {
  background: var(--color-warning-soft);
  border-color: var(--color-warning-border);
  color: var(--color-warning);

  strong {
    color: var(--color-text);
  }
}

@media (max-width: 1024px) {
  .top-bar {
    grid-template-columns: 1fr auto;
  }

  .top-bar__status,
  .top-bar__search {
    grid-column: 1 / -1;
  }
}

@media (max-width: 640px) {
  .top-bar {
    gap: var(--space-3);
    padding: var(--space-3);
  }

  .top-bar__pending {
    justify-self: end;
  }
}
</style>
