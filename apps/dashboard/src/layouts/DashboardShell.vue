<template>
  <div class="dashboard-shell">
    <AppTopBar />
    <div class="dashboard-shell__body" :class="{ 'dashboard-shell__body--collapsed': isSidebarCollapsed }">
      <AppSidebar :is-collapsed="isSidebarCollapsed" @toggle-collapse="handleToggleSidebar" />
      <main class="dashboard-shell__workspace" aria-label="Dashboard workspace">
        <RouterView v-slot="{ Component, route }">
          <KeepAlive>
            <component :is="Component" v-if="route.meta.keepAlive" :key="String(route.name ?? route.path)" />
          </KeepAlive>
          <component :is="Component" v-if="!route.meta.keepAlive" :key="route.fullPath" />
        </RouterView>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";

import AppSidebar from "../components/AppSidebar.vue";
import AppTopBar from "../components/AppTopBar.vue";

defineOptions({
  name: "DashboardShell",
});

const isSidebarCollapsed = ref(false);

function handleToggleSidebar(): void {
  isSidebarCollapsed.value = !isSidebarCollapsed.value;
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
  overflow: hidden;
}

@media (max-width: 768px) {
  .dashboard-shell__body,
  .dashboard-shell__body--collapsed {
    grid-template-columns: 1fr;
  }
}
</style>
