<template>
  <section class="system-page workspace-panel" aria-labelledby="system-title">
    <header class="page-header"><div><p>运行状态</p><h1 id="system-title">系统状态</h1></div><button class="page-action" type="button" :aria-busy="store.isRefreshing" :disabled="store.isRefreshing" @click="handleRefresh">立即检查</button></header>
    <div class="system-grid">
      <article v-for="item in statusItems" :key="item.label" class="status-item">
        <div><span>{{ item.label }}</span><small>{{ item.detail }}</small></div>
        <StatusBadge :label="item.value" :tone="item.tone" />
      </article>
    </div>
    <section v-if="store.status === 'error' && store.error" class="system-alert" role="alert"><strong>最近错误</strong><p>{{ store.error }}</p></section>
  </section>
</template>
<script setup lang="ts">
import { computed } from "vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";
defineOptions({ name: "SystemPage" });
const store = useDashboardStore();
const auth = useAuthStore();
const statusItems = computed(() => [
  { label: "Guard API", value: stateLabel(store.health.api), detail: store.health.checkedAt ? `检查于 ${formatTime(store.health.checkedAt)}` : "尚未检查", tone: stateTone(store.health.api) },
  { label: "PostgreSQL", value: stateLabel(store.health.database), detail: "审计与审批数据", tone: stateTone(store.health.database) },
  { label: "浏览器会话", value: auth.isAuthenticated ? "有效" : "异常", detail: auth.expiresAt ? `到期 ${formatTime(auth.expiresAt)}` : auth.error ?? "未建立会话", tone: auth.isAuthenticated ? "success" as const : "danger" as const },
  { label: "审计轮询", value: store.status === "ready" ? "实时" : store.status === "stale" ? "陈旧" : store.status === "error" ? "异常" : "同步中", detail: store.lastUpdatedAt ? `最近更新 ${formatTime(store.lastUpdatedAt)}` : "等待首次数据", tone: store.status === "ready" ? "success" as const : store.status === "stale" ? "warning" as const : store.status === "error" ? "danger" as const : "neutral" as const },
  { label: "数据源", value: store.dataSourceMode === "api" ? "Guard API" : "本地场景", detail: "当前数据连接", tone: "neutral" as const },
  { label: "审批队列", value: `${store.pendingCount} 待处理`, detail: "允许一次或拒绝", tone: store.pendingCount ? "warning" as const : "success" as const },
]);
function stateLabel(value: "online" | "offline" | "unknown") { return value === "online" ? "正常" : value === "offline" ? "异常" : "未知"; }
function stateTone(value: "online" | "offline" | "unknown") { return value === "online" ? "success" as const : value === "offline" ? "danger" as const : "neutral" as const; }
function formatTime(value: string) { return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }
function handleRefresh() { void store.refresh(); }
</script>
<style scoped lang="scss">
.system-page { display: grid; gap: var(--space-5); }
.system-grid { display: grid; gap: var(--space-3); grid-template-columns: repeat(3, 1fr); }
.status-item { align-items: center; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); display: flex; gap: var(--space-4); justify-content: space-between; min-height: 6rem; padding: var(--space-4); }
.status-item span { display: block; font-weight: var(--font-weight-bold); }
.status-item small { color: var(--color-text-subtle); display: block; margin-top: var(--space-1); }
.system-alert { background: var(--color-danger-soft); border: 1px solid var(--color-danger-border); border-radius: var(--radius-2); padding: var(--space-4); }
.system-alert p { color: var(--color-text-muted); margin: var(--space-1) 0 0; }
@media (max-width: 900px) { .system-grid { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 600px) { .system-grid { grid-template-columns: 1fr; } }
</style>
