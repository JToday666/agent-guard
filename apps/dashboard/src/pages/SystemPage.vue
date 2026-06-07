<template>
  <section class="system-page workspace-panel" aria-labelledby="system-title">
    <header class="page-header">
      <div>
        <p>运维</p>
        <h1 id="system-title">系统</h1>
      </div>
      <StatusBadge label="核心在线" tone="success" />
    </header>

    <div class="system-grid">
      <section v-for="item in systemStatus" :key="item.label" class="content-section">
        <h2>{{ item.label }}</h2>
        <StatusBadge :label="item.value" :tone="getSystemTone(item.status)" />
      </section>
    </div>

    <section class="content-section">
      <h2>运行信号</h2>
      <div class="link-row">
        <RouterLink to="/events?type=adapter_error">适配器错误</RouterLink>
        <RouterLink to="/events?runtime=langgraph">LangGraph 事件</RouterLink>
      </div>
    </section>
  </section>
</template>

<script setup lang="ts">
import StatusBadge from "../components/StatusBadge.vue";
import { systemStatus } from "../mocks/dashboard-data";
import type { SystemStatusItem } from "../types/dashboard";

defineOptions({
  name: "SystemPage",
});

function getSystemTone(status: SystemStatusItem["status"]): "neutral" | "success" | "warning" | "danger" {
  if (status === "online") return "success";
  if (status === "stale" || status === "partial") return "warning";
  return "danger";
}
</script>

<style scoped lang="scss">
.system-page {
  display: grid;
  gap: var(--space-5);
}

.system-grid {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
}
</style>
