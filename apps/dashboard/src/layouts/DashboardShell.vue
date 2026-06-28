<template>
  <div class="dashboard-shell">
    <AppTopBar
      :api-status="dashboardStore.health.api"
      :data-status="dashboardStore.status"
      :pending-count="dashboardStore.pendingCount"
      :updated-at="dashboardStore.lastUpdatedAt"
    />
    <div class="dashboard-shell__body" :class="{ 'dashboard-shell__body--collapsed': isSidebarCollapsed }">
      <AppSidebar
        :is-collapsed="isSidebarCollapsed"
        :pending-count="dashboardStore.pendingCount"
        @toggle-collapse="handleToggleSidebar"
      />
      <main class="dashboard-shell__workspace" aria-label="Dashboard workspace">
        <LoadingState
          v-if="authStore.status === 'idle' || authStore.status === 'loading'"
          class="session-loading"
          :rows="6"
        />
        <section v-else-if="authStore.status === 'error'" class="session-error" role="alert">
          <div>
            <strong>无法建立监督端会话</strong>
            <p>{{ authStore.error ?? "会话无效或启动链接已过期。" }}</p>
          </div>
          <button type="button" @click="handleInitializeDashboard">重新检查</button>
        </section>
        <template v-else>
          <section
            v-if="dashboardStore.status === 'stale' && dashboardStore.error"
            class="data-warning"
            role="status"
          >
            <span>部分数据暂未更新：{{ dashboardStore.error }}</span>
            <button
              type="button"
              :disabled="dashboardStore.isRefreshing"
              @click="handleRefreshDashboard"
            >
              重试
            </button>
          </section>
          <RouterView v-slot="{ Component, route }">
            <KeepAlive>
              <component :is="Component" v-if="route.meta.keepAlive" :key="String(route.name ?? route.path)" />
            </KeepAlive>
            <component :is="Component" v-if="!route.meta.keepAlive" :key="route.fullPath" />
          </RouterView>
        </template>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";

import AppSidebar from "../components/AppSidebar.vue";
import AppTopBar from "../components/AppTopBar.vue";
import LoadingState from "../components/States/LoadingState.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";

defineOptions({
  name: "DashboardShell",
});

const isSidebarCollapsed = ref(false);
const authStore = useAuthStore();
const dashboardStore = useDashboardStore();

async function handleInitializeDashboard(): Promise<void> {
  await authStore.bootstrap();
  if (authStore.isAuthenticated) {
    await dashboardStore.refresh();
    dashboardStore.startPolling();
  }
}

onMounted(handleInitializeDashboard);

onUnmounted(() => dashboardStore.stopPolling());

function handleToggleSidebar(): void {
  isSidebarCollapsed.value = !isSidebarCollapsed.value;
}


function handleRefreshDashboard(): void {
  void dashboardStore.refresh();
}
</script>

<style scoped lang="scss">
.dashboard-shell {
  background: var(--color-page);
  color: var(--color-text);
  min-height: 100vh;
}

.dashboard-shell__body {
  display: grid;
  grid-template-columns: var(--sidebar-width) minmax(0, 1fr);
  min-height: calc(100vh - var(--top-bar-height));
}

.dashboard-shell__body--collapsed {
  grid-template-columns: var(--sidebar-collapsed-width) minmax(0, 1fr);
}

.dashboard-shell__workspace {
  min-width: 0;
  overflow-x: auto;
  overflow-y: visible;
}

.session-error {
  align-items: center;
  background: var(--color-danger-soft);
  border: 1px solid var(--color-danger-border);
  border-radius: var(--radius-2);
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
  margin: var(--space-6);
  padding: var(--space-5);
}

.session-loading {
  margin: var(--space-6);
}

.session-error p { color: var(--color-text-muted); margin: var(--space-1) 0 0; }
.session-error button {
  background: var(--color-surface);
  border: 1px solid var(--color-danger-border);
  border-radius: var(--radius-2);
  color: var(--color-danger);
  cursor: pointer;
  min-height: 2.5rem;
  padding: 0 var(--space-4);
}

.data-warning {
  align-items: center;
  background: var(--color-warning-soft);
  border: 1px solid var(--color-warning-border);
  border-radius: var(--radius-2);
  box-shadow: var(--shadow-raised);
  color: var(--color-text-muted);
  display: flex;
  font-size: var(--font-size-13);
  gap: var(--space-3);
  justify-content: space-between;
  max-width: min(34rem, calc(100vw - 2 * var(--space-5)));
  padding: var(--space-3) var(--space-4);
  position: fixed;
  right: var(--space-5);
  top: calc(var(--top-bar-height) + var(--space-4));
  z-index: 40;
}

.data-warning button {
  background: var(--color-surface);
  border: 1px solid var(--color-warning-border);
  border-radius: var(--radius-2);
  color: var(--color-warning);
  cursor: pointer;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}

.data-warning button:disabled {
  cursor: wait;
  opacity: 0.65;
}

@media (max-width: 768px) {
  .dashboard-shell__body,
  .dashboard-shell__body--collapsed {
    grid-template-columns: 1fr;
  }

  .data-warning {
    left: var(--space-3);
    max-width: none;
    right: var(--space-3);
    top: var(--space-3);
  }
}
</style>
