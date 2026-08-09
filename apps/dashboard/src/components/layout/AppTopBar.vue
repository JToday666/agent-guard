<template>
  <header class="top-bar">
    <div class="top-bar__brand">
      <RouterLink
        class="top-bar__brand-link"
        to="/overview"
        aria-label="AgentGuard 智能体安全工作台"
      >
        <span class="top-bar__mark" aria-hidden="true"> <i></i><i></i><i></i> </span>
        <span>
          <strong>AgentGuard</strong>
          <small>智能体安全工作台</small>
        </span>
      </RouterLink>
    </div>

    <div class="top-bar__status" aria-label="全局状态">
      <RouterLink class="top-bar__status-link" to="/system">
        <StatusBadge :label="healthLabel" :tone="healthTone" />
      </RouterLink>
      <DataFreshness :status="dataStatus" :updated-at="updatedAt" />
    </div>

    <form class="top-bar__search" role="search" @submit.prevent="handleSearch">
      <label class="sr-only" for="global-search">搜索证据链、评测样本、资源或规则</label>
      <Search aria-hidden="true" :size="16" :stroke-width="1.8" />
      <input
        id="global-search"
        ref="searchInput"
        v-model.trim="searchText"
        aria-keyshortcuts="/"
        autocomplete="off"
        name="search"
        placeholder="搜索证据链、评测样本、资源或规则…"
        type="search"
        @keydown.esc="searchText = ''"
      />
      <kbd aria-hidden="true">/</kbd>
    </form>

    <RouterLink class="top-bar__pending" to="/approvals">
      <span>待审批</span>
      <strong>{{ pendingCount }}</strong>
    </RouterLink>
  </header>
</template>

<script setup lang="ts">
import { Search } from "@lucide/vue";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import type { DataStatus, HealthStatus } from "../../types/dashboard";
import DataFreshness from "../common/DataFreshness.vue";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({
  name: "AppTopBar",
});

const router = useRouter();
const searchInput = ref<HTMLInputElement | null>(null);
const searchText = ref("");
const props = defineProps<{
  apiStatus: HealthStatus["api"];
  dataStatus: DataStatus;
  databaseStatus: HealthStatus["database"];
  pendingCount: number;
  updatedAt: string | null;
}>();
const healthLabel = computed(() => {
  if (props.apiStatus === "offline") return "核心服务异常";
  if (props.databaseStatus === "offline") return "数据库异常";
  if (props.apiStatus === "online" && props.databaseStatus === "online") return "核心服务正常";
  return "核心服务未确认";
});
const healthTone = computed(() => {
  if (props.apiStatus === "offline" || props.databaseStatus === "offline") return "danger";
  if (props.apiStatus === "online" && props.databaseStatus === "online") return "success";
  return "neutral";
});

onMounted(() => window.addEventListener("keydown", handleSearchShortcut));
onBeforeUnmount(() => window.removeEventListener("keydown", handleSearchShortcut));

function handleSearchShortcut(event: KeyboardEvent): void {
  if (
    event.key !== "/" ||
    event.altKey ||
    event.ctrlKey ||
    event.metaKey ||
    event.target instanceof HTMLInputElement ||
    event.target instanceof HTMLTextAreaElement ||
    (event.target instanceof HTMLElement && event.target.isContentEditable)
  )
    return;
  event.preventDefault();
  searchInput.value?.focus();
}

function handleSearch(): void {
  void router.push({
    path: "/investigations",
    query: searchText.value ? { search: searchText.value } : {},
  });
}
</script>

<style scoped lang="scss">
.top-bar {
  align-items: center;
  background: var(--gradient-shell);
  border-bottom: 1px solid color-mix(in srgb, var(--color-shell-text) 12%, transparent);
  color: var(--color-shell-text);
  display: grid;
  gap: var(--space-5);
  grid-template-columns: minmax(11.5rem, 13.75rem) minmax(14rem, 1fr) minmax(17rem, 25rem) auto;
  height: var(--top-bar-height);
  min-height: var(--top-bar-height);
  padding: var(--space-2) var(--space-5);
  position: sticky;
  top: 0;
  z-index: 30;
}

.top-bar__brand,
.top-bar__status {
  min-width: 0;
}

.top-bar__brand-link {
  align-items: center;
  color: var(--color-shell-text);
  display: inline-flex;
  gap: var(--space-3);
  min-width: 0;
  text-decoration: none;
}

.top-bar__mark {
  align-items: end;
  background: color-mix(in srgb, var(--color-shell-text) 8%, transparent);
  border: 1px solid color-mix(in srgb, var(--color-shell-text) 18%, transparent);
  border-radius: var(--radius-2);
  display: inline-flex;
  flex: 0 0 auto;
  gap: 0.15rem;
  height: 2.25rem;
  justify-content: center;
  overflow: hidden;
  padding: 0.45rem;
  position: relative;
  width: 2.25rem;

  &::after {
    background: var(--gradient-brand);
    bottom: 0;
    content: "";
    height: 0.14rem;
    left: 0;
    position: absolute;
    right: 0;
  }

  i {
    background: var(--color-jade-bright);
    border-radius: var(--radius-pill);
    display: block;
    width: 0.19rem;

    &:nth-child(1) {
      height: 42%;
      opacity: 0.7;
    }

    &:nth-child(2) {
      height: 78%;
    }

    &:nth-child(3) {
      height: 58%;
      opacity: 0.82;
    }
  }
}

.top-bar__brand-link strong {
  background: var(--gradient-brand-text);
  background-clip: text;
  display: block;
  font-size: var(--font-size-18);
  font-weight: var(--font-weight-bold);
  letter-spacing: -0.02em;
  line-height: var(--line-height-tight);
  -webkit-text-fill-color: transparent;
}

.top-bar__brand-link small {
  color: var(--color-shell-muted);
  display: block;
  font-size: var(--font-size-11);
  margin-top: 0.15rem;
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

.top-bar :deep(.freshness) {
  color: var(--color-shell-muted);
}

.top-bar :deep(.status-badge) {
  background: color-mix(in srgb, var(--color-shell-text) 8%, transparent);
  border-color: color-mix(in srgb, var(--color-shell-text) 15%, transparent);
  color: var(--color-shell-text);
}

.top-bar :deep(.status-badge--success) {
  border-color: color-mix(in srgb, var(--color-jade-bright) 52%, transparent);
  color: color-mix(in srgb, var(--color-jade-bright) 72%, var(--color-shell-text));
}

.top-bar :deep(.status-badge--danger) {
  border-color: color-mix(in srgb, var(--color-danger) 58%, transparent);
  color: color-mix(in srgb, var(--color-danger) 62%, var(--color-shell-text));
}

.top-bar__search {
  align-items: center;
  background: color-mix(in srgb, var(--color-shell-text) 7%, transparent);
  border: 1px solid color-mix(in srgb, var(--color-shell-text) 17%, transparent);
  border-radius: var(--radius-2);
  color: var(--color-shell-muted);
  display: grid;
  gap: var(--space-2);
  grid-template-columns: auto minmax(0, 1fr) auto;
  min-width: 0;
  padding: 0 var(--space-3);

  &:focus-within {
    border-color: var(--color-jade-bright);
    box-shadow: var(--glow-active);
  }

  input {
    appearance: none;
    background: transparent;
    border: 0;
    color: var(--color-shell-text);
    min-height: 2.25rem;
    min-width: 0;
    outline: 0;
    padding: 0;
    width: 100%;

    &::placeholder {
      color: var(--color-shell-muted);
    }

    &::-webkit-search-cancel-button {
      filter: grayscale(1) invert(1);
      opacity: 0.7;
    }
  }

  kbd {
    border: 1px solid color-mix(in srgb, var(--color-shell-text) 18%, transparent);
    border-radius: var(--radius-1);
    color: var(--color-shell-muted);
    font-size: var(--font-size-11);
    line-height: 1.2rem;
    min-width: 1.2rem;
    text-align: center;
  }
}

.top-bar__pending {
  align-items: center;
  background: color-mix(in srgb, var(--color-warning) 20%, transparent);
  border: 1px solid color-mix(in srgb, var(--color-warning-border) 62%, transparent);
  border-radius: var(--radius-2);
  color: color-mix(in srgb, var(--color-warning-border) 72%, var(--color-shell-text));
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-2);
  min-height: 2.25rem;
  padding: 0 var(--space-3);
  text-decoration: none;
  white-space: nowrap;

  strong {
    align-items: center;
    background: var(--color-warning);
    border-radius: var(--radius-pill);
    color: var(--color-text-inverse);
    display: inline-flex;
    font-variant-numeric: tabular-nums;
    height: 1.3rem;
    justify-content: center;
    min-width: 1.3rem;
    padding: 0 0.3rem;
  }

  &:hover {
    background: color-mix(in srgb, var(--color-warning) 30%, transparent);
    border-color: var(--color-warning-border);
    transform: translateY(-1px);
  }
}

@media (max-width: 82rem) {
  .top-bar {
    gap: var(--space-3);
    grid-template-columns: 11.5rem minmax(13rem, 1fr) minmax(15rem, 20rem) auto;
    padding-inline: var(--space-4);
  }

  .top-bar__brand-link small {
    display: none;
  }
}

@media (max-width: 56.25rem) {
  .top-bar {
    column-gap: var(--space-2);
    grid-template-areas:
      "brand status pending"
      "search search search";
    grid-template-columns: minmax(8.5rem, 1fr) auto auto;
    grid-template-rows: minmax(2.25rem, auto) 2.5rem;
    height: var(--top-bar-height);
    padding: var(--space-2) var(--space-3);
    row-gap: var(--space-2);
  }

  .top-bar__brand {
    grid-area: brand;
  }

  .top-bar__status {
    flex-wrap: nowrap;
    grid-area: status;
  }

  .top-bar__search {
    grid-area: search;
  }

  .top-bar__pending {
    grid-area: pending;
  }
}
</style>
