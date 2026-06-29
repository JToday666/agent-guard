<template>
  <header class="top-bar">
    <div class="top-bar__brand">
      <RouterLink class="top-bar__title" to="/overview">AgentGuard</RouterLink>
      <span class="top-bar__subtitle">安全监督工作台</span>
    </div>

    <div class="top-bar__status" aria-label="全局状态">
      <RouterLink class="top-bar__status-link" to="/system">
        <StatusBadge :label="healthLabel" :tone="healthTone" />
      </RouterLink>
      <DataFreshness :status="dataStatus" :updated-at="updatedAt" />
    </div>

    <form class="top-bar__search" role="search" @submit.prevent="handleSearch">
      <label class="sr-only" for="global-search">搜索证据链、Case、资源或规则</label>
      <input
        id="global-search"
        v-model.trim="searchText"
        name="search"
        placeholder="搜索证据链 / Case / 资源 / 规则"
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
import { computed, ref } from "vue";
import { useRouter } from "vue-router";

import type { DataStatus, HealthStatus } from "../../types/dashboard";
import DataFreshness from "../common/DataFreshness.vue";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({
  name: "AppTopBar",
});

const router = useRouter();
const searchText = ref("");
const props = defineProps<{
  apiStatus: HealthStatus["api"];
  dataStatus: DataStatus;
  pendingCount: number;
  updatedAt: string | null;
}>();
const healthLabel = computed(() => props.apiStatus === "online" ? "Guard API 正常" : props.apiStatus === "offline" ? "Guard API 异常" : "Guard API 未知");
const healthTone = computed(() => props.apiStatus === "online" ? "success" as const : props.apiStatus === "offline" ? "danger" as const : "neutral" as const);

function handleSearch(): void {
  void router.push({ path: "/investigations", query: searchText.value ? { search: searchText.value } : {} });
}
</script>

<style scoped lang="scss">
.top-bar {
  align-items: center;
  background: rgb(255 255 255 / 0.92);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(10rem, 14rem) minmax(13rem, 1fr) minmax(12rem, 22rem) auto;
  height: var(--top-bar-height);
  min-height: var(--top-bar-height);
  padding: var(--space-2) var(--space-5);
  position: sticky;
  top: 0;
  z-index: 20;
}

.top-bar__brand,
.top-bar__status {
  min-width: 0;
}

.top-bar__title {
  background: linear-gradient(135deg, #101828 30%, #155eef);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  display: block;
  font-size: var(--font-size-18);
  font-weight: var(--font-weight-bold);
  line-height: var(--line-height-tight);
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

.top-bar__pending {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-pill);
  color: var(--color-text-muted);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-2);
  min-height: 1.75rem;
  padding: 0 var(--space-3);
  text-decoration: none;
  white-space: nowrap;

  &:hover {
    background: var(--color-active-soft);
    border-color: var(--color-active-border);
    color: var(--color-active);
  }
}

.top-bar__search {
  min-width: 0;

  input {
    background: var(--color-page-strong);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    color: var(--color-text);
    min-height: 2.25rem;
    padding: 0 var(--space-3);
    width: 100%;

    &::placeholder {
      color: var(--color-text-subtle);
    }

    &:hover {
      border-color: var(--color-border-strong);
    }
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
    grid-template-columns: minmax(10rem, 1fr) minmax(12rem, 22rem) auto;
  }

  .top-bar__status {
    display: none;
  }
}

@media (max-width: 640px) {
  .top-bar {
    gap: var(--space-3);
    grid-template-columns: 1fr auto;
    height: auto;
    padding: var(--space-3);
  }

  .top-bar__search {
    grid-column: 1 / -1;
  }

  .top-bar__pending {
    justify-self: end;
  }

  .top-bar__subtitle {
    display: none;
  }
}
</style>
