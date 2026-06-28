<template>
  <nav class="sidebar" :class="{ 'sidebar--collapsed': isCollapsed }" aria-label="主导航">
    <div class="sidebar__header">
      <span v-if="!isCollapsed" class="sidebar__title">导航</span>
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

    <button
      class="sidebar__toggle"
      type="button"
      :aria-expanded="isOpen"
      aria-controls="sidebar-links"
      @click="isOpen = !isOpen"
    >
      菜单
    </button>

    <div id="sidebar-links" class="sidebar__links" :class="{ 'sidebar__links--open': isOpen }">
      <section v-for="group in navigationGroups" :key="group.label" class="sidebar__group">
        <h2>{{ group.label }}</h2>
        <RouterLink
          v-for="item in group.items"
          :key="item.to"
          class="sidebar__link"
          :class="{ 'sidebar__link--active': isNavigationItemActive(item.to) }"
          :to="item.to"
          :aria-current="isNavigationItemActive(item.to) ? 'page' : undefined"
          :title="isCollapsed ? item.label : undefined"
          :aria-label="item.meta ? `${item.label}，${item.meta}` : item.label"
          @click="isOpen = false"
        >
          <span class="sidebar__icon" aria-hidden="true">
            <component :is="item.icon" :size="19" />
          </span>
          <span class="sidebar__label">{{ item.label }}</span>
          <small v-if="item.meta" class="sidebar__meta">{{ item.meta }}</small>
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
  ScanSearch,
  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  Server,
} from "@lucide/vue";
import { computed, ref } from "vue";
import { useRoute } from "vue-router";

defineOptions({
  name: "AppSidebar",
});

const emit = defineEmits<{
  "toggle-collapse": [];
}>();

const route = useRoute();
const isOpen = ref(false);
const props = defineProps<{
  isCollapsed: boolean;
  pendingCount: number;
}>();

const navigationGroups = computed(() => [
  {
    label: "监控",
    items: [
      { icon: LayoutDashboard, label: "安全总览", to: "/overview" },
      { icon: ScanSearch, label: "事件调查", to: "/investigations" },
      {
        count: props.pendingCount,
        icon: CircleCheckBig,
        label: "人工审批",
        meta: `${props.pendingCount} 待处理`,
        to: "/approvals",
      },
    ],
  },
  {
    label: "评测",
    items: [{ icon: ChartNoAxesColumn, label: "安全评测", to: "/evaluation" }],
  },
  {
    label: "运维",
    items: [
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
  background: rgb(255 255 255 / 0.72);
  border-right: 1px solid var(--color-border);
  height: calc(100vh - var(--top-bar-height));
  overflow-y: auto;
  padding: var(--space-5) var(--space-3);
  position: sticky;
  top: var(--top-bar-height);
}

.sidebar__header {
  align-items: center;
  display: flex;
  gap: var(--space-2);
  justify-content: space-between;
  margin-bottom: var(--space-4);
  min-height: 2.375rem;
}

.sidebar__title {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-bold);
}

.sidebar__collapse {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-3);
  color: var(--color-text-muted);
  cursor: pointer;
  display: inline-flex;
  height: 2.375rem;
  justify-content: center;
  width: 2.375rem;

  &:hover {
    background: var(--color-active-soft);
    border-color: var(--color-active-border);
    color: var(--color-active);
  }
}

.sidebar__toggle {
  display: none;
}

.sidebar__links {
  display: grid;
  gap: var(--space-5);
}

.sidebar__group {
  display: grid;
  gap: var(--space-2);

  h2 {
    color: var(--color-text-subtle);
    font-size: var(--font-size-12);
    font-weight: var(--font-weight-bold);
    letter-spacing: 0;
    margin: 0;
    text-transform: uppercase;
  }
}

.sidebar__link {
  align-items: center;
  border-radius: var(--radius-3);
  color: var(--color-text-muted);
  display: grid;
  gap: var(--space-2);
  grid-template-columns: 1.5rem minmax(0, 1fr) auto;
  min-height: 2.375rem;
  min-width: 0;
  padding: 0 var(--space-3);
  text-decoration: none;

  &:hover {
    background: var(--color-active-soft);
    color: var(--color-text);
  }

  .sidebar__label,
  .sidebar__meta,
  small {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  small {
    color: var(--color-text-subtle);
    font-size: var(--font-size-11);
  }
}

.sidebar__icon {
  align-items: center;
  display: inline-flex;
  justify-content: center;
}

.sidebar__badge {
  align-items: center;
  background: #9f1239;
  border: 2px solid var(--color-nav);
  border-radius: var(--radius-pill);
  box-shadow: 0 4px 10px rgb(159 18 57 / 0.28);
  color: #ffffff !important;
  display: none;
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  height: 1.25rem;
  justify-content: center;
  min-width: 1.25rem;
  padding: 0 0.3125rem;
  position: absolute;
  right: 0.125rem;
  top: 0.125rem;
}

.sidebar__link.router-link-active,
.sidebar__link--active {
  background: linear-gradient(90deg, var(--color-active-soft), transparent 88%);
  box-shadow: inset 3px 0 var(--color-active);
  color: var(--color-active);
  font-weight: var(--font-weight-bold);

  small {
    color: var(--color-active);
  }

  .sidebar__badge {
    border-color: var(--color-active-soft);
    color: #ffffff !important;
  }
}

.sidebar--collapsed {
  padding: var(--space-3);

  .sidebar__header {
    justify-content: center;
  }

  .sidebar__links {
    gap: var(--space-3);
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
    position: relative;
  }

  .sidebar__label,
  .sidebar__meta {
    display: none;
  }

  .sidebar__badge {
    display: inline-flex;
  }
}

@media (max-width: 768px) {
  .sidebar {
    align-self: auto;
    border-bottom: 1px solid var(--color-border);
    border-right: 0;
    height: auto;
    overflow: visible;
    padding: var(--space-3);
    position: static;
  }

  .sidebar__header {
    display: none;
  }

  .sidebar__toggle {
    align-items: center;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    color: var(--color-text);
    cursor: pointer;
    display: inline-flex;
    font-weight: var(--font-weight-semibold);
    min-height: 2.25rem;
    padding: 0 var(--space-3);
  }

  .sidebar__links {
    display: none;
    margin-top: var(--space-3);
  }

  .sidebar__links--open {
    display: grid;
  }

  .sidebar--collapsed {
    .sidebar__group h2 {
      height: auto;
      margin: 0;
      overflow: visible;
      position: static;
      white-space: normal;
      width: auto;
    }

    .sidebar__link {
      grid-template-columns: 1.5rem minmax(0, 1fr) auto;
      justify-items: start;
      padding: 0 var(--space-3);
    }

    .sidebar__label,
    .sidebar__meta {
      display: inline;
    }

    .sidebar__badge {
      display: none;
    }
  }
}
</style>
