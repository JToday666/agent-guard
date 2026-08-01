<template>
  <nav class="sidebar" :class="{ 'sidebar--collapsed': isCollapsed }" aria-label="主导航">
    <div class="sidebar__header">
      <span v-if="!isCollapsed" class="sidebar__title">工作台</span>
      <button
        class="sidebar__collapse"
        type="button"
        :aria-label="isCollapsed ? '展开侧栏' : '收起侧栏'"
        :title="isCollapsed ? '展开侧栏' : '收起侧栏'"
        @click="emit('toggle-collapse')"
      >
        <PanelLeftOpen v-if="isCollapsed" aria-hidden="true" :size="18" />
        <PanelLeftClose v-else aria-hidden="true" :size="18" />
      </button>
    </div>

    <div class="sidebar__links">
      <section v-for="group in navigationGroups" :key="group.label" class="sidebar__group">
        <h2>{{ group.label }}</h2>
        <RouterLink
          v-for="item in group.items"
          :key="item.to"
          class="sidebar__link"
          :class="{ 'sidebar__link--active': isNavigationItemActive(item.to) }"
          :to="item.to"
          :aria-current="isNavigationItemActive(item.to) ? 'page' : undefined"
          :aria-label="item.count ? `${item.label}，${item.count} 项待处理` : item.label"
          :title="isCollapsed ? item.label : undefined"
          @focus="preloadDashboardRoute(item.to)"
          @pointerenter="preloadDashboardRoute(item.to)"
        >
          <span class="sidebar__icon" aria-hidden="true">
            <component :is="item.icon" :size="18" :stroke-width="1.8" />
          </span>
          <span class="sidebar__label">{{ item.label }}</span>
          <small v-if="item.count" class="sidebar__badge">{{ item.count }}</small>
        </RouterLink>
      </section>
    </div>
  </nav>
</template>

<script setup lang="ts">
import {
  ChartNoAxesColumn,
  CircleCheckBig,
  GitBranch,
  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  ScanSearch,
  Server,
} from "@lucide/vue";
import { computed } from "vue";
import { useRoute } from "vue-router";
import { preloadDashboardRoute } from "../../router/dashboard-page-loaders";

defineOptions({
  name: "AppSidebar",
});

const emit = defineEmits<{
  "toggle-collapse": [];
}>();

const route = useRoute();
const props = defineProps<{
  isCollapsed: boolean;
  pendingCount: number;
}>();

const navigationGroups = computed(() => [
  {
    label: "观察与处置",
    items: [
      { icon: LayoutDashboard, label: "安全总览", to: "/overview" },
      { icon: ScanSearch, label: "事件调查", to: "/investigations" },
      {
        count: props.pendingCount,
        icon: CircleCheckBig,
        label: "人工审批",
        to: "/approvals",
      },
      { icon: GitBranch, label: "证据链", to: "/evidence" },
    ],
  },
  {
    label: "验证与运行",
    items: [
      { icon: ChartNoAxesColumn, label: "安全评测", to: "/evaluation" },
      { icon: Server, label: "系统状态", to: "/system" },
    ],
  },
]);

function isNavigationItemActive(path: string): boolean {
  return route.path === path || route.path.startsWith(`${path}/`);
}
</script>

<style scoped lang="scss">
.sidebar {
  align-self: start;
  background: color-mix(in srgb, var(--color-nav) 90%, transparent);
  border-right: 1px solid var(--color-border);
  height: calc(100vh - var(--top-bar-height));
  overflow-y: auto;
  padding: var(--space-4) var(--space-3);
  position: sticky;
  top: var(--top-bar-height);
}

.sidebar__header {
  align-items: center;
  display: flex;
  gap: var(--space-2);
  justify-content: space-between;
  margin-bottom: var(--space-5);
  min-height: 2.25rem;
  padding: 0 var(--space-2);
}

.sidebar__title {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  letter-spacing: 0.08em;
}

.sidebar__collapse {
  align-items: center;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-2);
  color: var(--color-text-subtle);
  display: inline-flex;
  height: 2.25rem;
  justify-content: center;
  width: 2.25rem;

  &:hover {
    background: var(--color-active-soft);
    border-color: var(--color-active-border);
    color: var(--color-active-strong);
  }
}

.sidebar__links {
  display: grid;
  gap: var(--space-6);
}

.sidebar__group {
  display: grid;
  gap: var(--space-1);

  h2 {
    color: var(--color-text-subtle);
    font-size: var(--font-size-11);
    font-weight: var(--font-weight-bold);
    letter-spacing: 0.075em;
    margin: 0 0 var(--space-2);
    padding: 0 var(--space-3);
  }
}

.sidebar__link {
  align-items: center;
  border: 1px solid transparent;
  border-radius: var(--radius-2);
  color: var(--color-text-muted);
  display: grid;
  font-size: var(--font-size-13);
  gap: var(--space-2);
  grid-template-columns: 1.5rem minmax(0, 1fr) auto;
  min-height: 2.5rem;
  min-width: 0;
  padding: 0 var(--space-3);
  position: relative;
  text-decoration: none;

  &::before {
    background: transparent;
    border-radius: var(--radius-pill);
    content: "";
    height: 1.25rem;
    left: -1px;
    position: absolute;
    width: 0.1875rem;
  }

  &:hover {
    background: var(--color-active-soft);
    color: var(--color-text);
  }
}

.sidebar__label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sidebar__icon {
  align-items: center;
  display: inline-flex;
  justify-content: center;
}

.sidebar__badge {
  align-items: center;
  background: var(--color-warning);
  border-radius: var(--radius-pill);
  color: var(--color-text-inverse);
  display: inline-flex;
  font-size: var(--font-size-11);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-bold);
  height: 1.25rem;
  justify-content: center;
  min-width: 1.25rem;
  padding: 0 0.35rem;
}

.sidebar__link.router-link-active,
.sidebar__link--active {
  background: var(--gradient-active-row);
  border-color: color-mix(in srgb, var(--color-active-border) 52%, transparent);
  color: var(--color-active-strong);
  font-weight: var(--font-weight-semibold);

  &::before {
    background: var(--gradient-active-track);
    box-shadow: var(--glow-active);
  }

  .sidebar__icon {
    color: var(--color-active);
  }
}

.sidebar--collapsed {
  padding: var(--space-4) var(--space-2);

  .sidebar__header {
    justify-content: center;
    padding: 0;
  }

  .sidebar__links {
    gap: var(--space-4);
  }

  .sidebar__group {
    gap: var(--space-2);
  }

  .sidebar__group h2 {
    height: 1px;
    margin: -1px;
    overflow: hidden;
    position: absolute;
    white-space: nowrap;
    width: 1px;
  }

  .sidebar__link {
    grid-template-columns: 1fr;
    justify-items: center;
    padding: 0;
  }

  .sidebar__label {
    display: none;
  }

  .sidebar__badge {
    border: 2px solid var(--color-nav);
    box-shadow: var(--shadow-subtle);
    position: absolute;
    right: -0.1rem;
    top: -0.15rem;
  }
}
</style>
