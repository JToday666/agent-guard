<template>
  <div class="dashboard-shell">
    <a class="skip-link" href="#main-content" @click="handleSkipToMain">跳到主要内容</a>
    <AppTopBar
      :api-status="dashboardStore.health.api"
      :data-status="dashboardStore.status"
      :database-status="dashboardStore.health.database"
      :pending-count="dashboardStore.pendingCount"
      :updated-at="dashboardStore.lastUpdatedAt"
    />
    <div
      class="dashboard-shell__body"
      :class="{
        'dashboard-shell__body--collapsed': isTabletShell || isSidebarCollapsed,
        'dashboard-shell__body--tablet': isTabletShell,
      }"
    >
      <AppSidebar
        :is-collapsed="effectiveSidebarCollapsed"
        :is-tablet="isTabletShell"
        :pending-count="dashboardStore.pendingCount"
        @navigate="handleTabletNavigation"
        @toggle-collapse="handleToggleSidebar"
      />
      <button
        v-if="isTabletShell && isTabletSidebarExpanded"
        class="dashboard-shell__sidebar-backdrop"
        type="button"
        aria-label="收起侧栏"
        @click="handleCloseTabletSidebar(true)"
      ></button>
      <main
        id="main-content"
        class="dashboard-shell__workspace"
        aria-label="主要工作区"
        tabindex="-1"
      >
        <LoadingState
          v-if="authStore.status === 'idle' || authStore.status === 'loading'"
          class="session-loading"
          :rows="6"
        />
        <InlineNotice
          v-else-if="authStore.status === 'error'"
          class="session-error"
          title="无法建立安全会话"
          tone="danger"
        >
          <p>{{ authStore.error ?? "会话无效或启动链接已过期。" }}</p>
          <template #action>
            <button type="button" @click="handleInitializeDashboard">重新检查</button>
          </template>
        </InlineNotice>
        <template v-else>
          <InlineNotice
            v-if="dashboardStore.status === 'stale' && dashboardStore.error"
            class="data-warning"
            title="部分数据暂未更新"
            tone="warning"
          >
            <p>{{ dashboardStore.error }}</p>
            <template #action>
              <button
                type="button"
                :disabled="dashboardStore.isManualRefreshing"
                @click="handleRefreshDashboard"
              >
                {{ dashboardStore.isManualRefreshing ? "重试中…" : "重试" }}
              </button>
            </template>
          </InlineNotice>
          <ErrorState
            v-if="routeRenderFailed"
            class="route-error"
            title="页面渲染异常"
            message="当前页面暂时无法渲染，请重新加载 Dashboard。"
            @retry="handleReloadDashboard"
          />
          <RouterView v-else v-slot="{ Component, route: viewRoute }">
            <div class="dashboard-route-stage">
              <Transition name="dashboard-route">
                <KeepAlive v-if="viewRoute.meta.keepAlive">
                  <component
                    :is="Component"
                    :key="String(viewRoute.name ?? viewRoute.path)"
                    class="dashboard-route-view"
                  />
                </KeepAlive>
                <component
                  :is="Component"
                  v-else
                  :key="viewRoute.fullPath"
                  class="dashboard-route-view"
                />
              </Transition>
            </div>
          </RouterView>
        </template>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onErrorCaptured, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute } from "vue-router";

import InlineNotice from "../components/common/InlineNotice.vue";
import AppSidebar from "../components/layout/AppSidebar.vue";
import AppTopBar from "../components/layout/AppTopBar.vue";
import { schedulePrimaryRoutePreload } from "../router/dashboard-page-loaders";
import ErrorState from "../components/states/ErrorState.vue";
import LoadingState from "../components/states/LoadingState.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";
import { getDashboardRefreshScope } from "../utils/dashboard-refresh-scope";

defineOptions({
  name: "DashboardShell",
});

const isSidebarCollapsed = ref(false);
const isTabletShell = ref(false);
const isTabletSidebarExpanded = ref(false);
const routeRenderFailed = ref(false);
const authStore = useAuthStore();
const dashboardStore = useDashboardStore();
const route = useRoute();
let cancelRoutePreload: (() => void) | null = null;
let tabletShellMedia: MediaQueryList | null = null;

const effectiveSidebarCollapsed = computed(() =>
  isTabletShell.value ? !isTabletSidebarExpanded.value : isSidebarCollapsed.value,
);

async function handleInitializeDashboard(): Promise<void> {
  dashboardStore.setActiveScope(getDashboardRefreshScope(route.name));
  await authStore.bootstrap();
  if (authStore.isAuthenticated) {
    await dashboardStore.refresh(undefined, "initial");
    dashboardStore.startPolling();
    cancelRoutePreload?.();
    cancelRoutePreload = schedulePrimaryRoutePreload();
  }
}

onMounted(handleInitializeDashboard);
onMounted(() => {
  tabletShellMedia = window.matchMedia("(max-width: 74.9375rem)");
  updateTabletShell(tabletShellMedia);
  tabletShellMedia.addEventListener("change", updateTabletShell);
  window.addEventListener("keydown", handleShellEscape);
});
onUnmounted(() => {
  cancelRoutePreload?.();
  dashboardStore.stopPolling();
  tabletShellMedia?.removeEventListener("change", updateTabletShell);
  window.removeEventListener("keydown", handleShellEscape);
});

function handleToggleSidebar(): void {
  if (isTabletShell.value) {
    isTabletSidebarExpanded.value = !isTabletSidebarExpanded.value;
    return;
  }
  isSidebarCollapsed.value = !isSidebarCollapsed.value;
}

function updateTabletShell(media: MediaQueryList | MediaQueryListEvent): void {
  isTabletShell.value = media.matches;
  if (!media.matches) isTabletSidebarExpanded.value = false;
}

function handleTabletNavigation(): void {
  if (isTabletShell.value) isTabletSidebarExpanded.value = false;
}

function handleCloseTabletSidebar(restoreFocus = false): void {
  if (!isTabletSidebarExpanded.value) return;
  isTabletSidebarExpanded.value = false;
  if (restoreFocus) {
    void nextTick().then(() => document.querySelector<HTMLElement>(".sidebar__collapse")?.focus());
  }
}

function handleShellEscape(event: KeyboardEvent): void {
  if (event.key === "Escape" && isTabletShell.value && isTabletSidebarExpanded.value) {
    handleCloseTabletSidebar(true);
  }
}

function handleSkipToMain(event: MouseEvent): void {
  event.preventDefault();
  document.querySelector<HTMLElement>("#main-content")?.focus();
}

function handleRefreshDashboard(): void {
  void dashboardStore.refresh(undefined, "manual");
}

function handleReloadDashboard(): void {
  window.location.reload();
}

watch(
  () => route.name,
  (routeName) => {
    const nextScope = getDashboardRefreshScope(routeName);
    const scopeChanged = dashboardStore.activeScope !== nextScope;
    dashboardStore.setActiveScope(nextScope);
    if (scopeChanged && authStore.isAuthenticated) {
      void dashboardStore.refresh(nextScope, "navigation");
    }
  },
  { immediate: true },
);

watch(
  () => route.fullPath,
  () => {
    routeRenderFailed.value = false;
    handleTabletNavigation();
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
  min-height: 100dvh;
}

.dashboard-shell__body {
  display: grid;
  grid-template-columns: var(--sidebar-width) minmax(0, 1fr);
  min-height: calc(100dvh - var(--top-bar-height));
}

.dashboard-shell__body--collapsed {
  grid-template-columns: var(--sidebar-collapsed-width) minmax(0, 1fr);
}

.dashboard-shell__body--tablet {
  position: relative;
}

.dashboard-shell__workspace {
  min-width: 0;
  outline: 0;
}
.dashboard-shell__workspace:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: -2px;
}

.dashboard-route-stage {
  min-width: 0;
  position: relative;
}

.dashboard-route-view {
  display: block;
}

.dashboard-route-enter-active {
  transition: opacity var(--transition-route);
}

.dashboard-route-leave-active {
  inset: 0;
  opacity: 0;
  pointer-events: none;
  position: absolute;
  width: 100%;
}

.dashboard-route-enter-from {
  opacity: 0;
}

.skip-link {
  background: var(--color-surface);
  border: 2px solid var(--color-focus);
  border-radius: var(--radius-2);
  color: var(--color-text);
  font-weight: var(--font-weight-semibold);
  left: var(--space-4);
  padding: var(--space-2) var(--space-3);
  position: fixed;
  top: var(--space-3);
  transform: translateY(-180%);
  z-index: 100;

  &:focus {
    transform: translateY(0);
  }
}

.session-error,
.session-loading,
.route-error {
  margin: var(--space-6);
}

.data-warning {
  max-width: min(36rem, calc(100vw - 2 * var(--space-5)));
  position: fixed;
  right: var(--space-5);
  top: calc(var(--top-bar-height) + var(--space-4));
  z-index: 40;
}

.dashboard-shell__sidebar-backdrop {
  background: color-mix(in srgb, var(--color-shell-strong) 28%, transparent);
  border: 0;
  bottom: 0;
  cursor: default;
  left: var(--sidebar-collapsed-width);
  padding: 0;
  position: fixed;
  right: 0;
  top: var(--top-bar-height);
  z-index: 20;
}

@media (max-width: 74.9375rem) {
  .dashboard-shell__body {
    grid-template-columns: var(--sidebar-collapsed-width) minmax(0, 1fr);
  }
}

@media (max-width: 56.25rem) {
  .dashboard-shell {
    --top-bar-height: 6.75rem;
  }
}

@media (prefers-reduced-motion: reduce) {
  .dashboard-route-enter-active,
  .dashboard-route-leave-active {
    transition: none;
  }

  .dashboard-route-enter-from {
    opacity: 1;
  }
}
</style>
