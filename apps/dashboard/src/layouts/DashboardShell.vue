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
          <section v-if="dashboardStore.status === 'stale' && dashboardStore.error" class="data-warning" role="status">
            <span>部分数据暂未更新：{{ dashboardStore.error }}</span>
            <button type="button" :disabled="dashboardStore.isRefreshing" @click="handleRefreshDashboard">重试</button>
          </section>
          <ErrorState
            v-if="routeRenderFailed"
            class="route-error"
            title="页面渲染异常"
            message="当前页面暂时无法渲染，请重新加载 Dashboard。"
            @retry="handleReloadDashboard"
          />
          <RouterView v-else v-slot="{ Component, route: routeRecord }">
            <div class="dashboard-route-stage">
              <Transition name="dashboard-route">
                <KeepAlive v-if="routeRecord.meta.keepAlive">
                  <component
                    :is="Component"
                    :key="String(routeRecord.name ?? routeRecord.path)"
                    class="dashboard-route-view"
                  />
                </KeepAlive>
                <component :is="Component" v-else :key="routeRecord.fullPath" class="dashboard-route-view" />
              </Transition>
            </div>
          </RouterView>
        </template>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onErrorCaptured, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute } from "vue-router";

import AppSidebar from "../components/layout/AppSidebar.vue";
import AppTopBar from "../components/layout/AppTopBar.vue";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";

defineOptions({
  name: "DashboardShell",
});

const isSidebarCollapsed = ref(false);
const routeRenderFailed = ref(false);
const authStore = useAuthStore();
const dashboardStore = useDashboardStore();
const route = useRoute();

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

function handleReloadDashboard(): void {
  window.location.reload();
}

watch(
  () => route.fullPath,
  () => {
    routeRenderFailed.value = false;
  },
);

onErrorCaptured(() => {
  routeRenderFailed.value = true;
  return false;
});
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

.dashboard-route-stage {
  min-width: 0;
  position: relative;
}

.dashboard-route-view {
  display: block;
}

.dashboard-route-enter-active,
.dashboard-route-leave-active {
  transition:
    opacity var(--transition-base),
    transform var(--transition-base);
  will-change: opacity, transform;
}

.dashboard-route-leave-active {
  inset: 0;
  pointer-events: none;
  position: absolute;
  width: 100%;
}

.dashboard-route-enter-from {
  opacity: 0;
  transform: translateY(4px);
}

.dashboard-route-leave-to {
  opacity: 0;
  transform: translateY(-3px);
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

.route-error {
  margin: var(--space-6);
}

.session-error p {
  color: var(--color-text-muted);
  margin: var(--space-1) 0 0;
}
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

@media (prefers-reduced-motion: reduce) {
  .dashboard-route-enter-active,
  .dashboard-route-leave-active {
    transition: none;
  }

  .dashboard-route-enter-from,
  .dashboard-route-leave-to {
    opacity: 1;
    transform: none;
  }
}
</style>
