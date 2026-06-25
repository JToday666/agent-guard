<template>
  <section class="system-page workspace-panel" aria-labelledby="system-title">
    <header class="page-header"><div><p>运行状态</p><h1 id="system-title">系统状态</h1></div><button class="page-action" type="button" :aria-busy="store.isRefreshing" :disabled="store.isRefreshing" @click="handleRefresh">{{ store.isRefreshing ? "检查中" : "立即检查" }}</button></header>
    <section class="status-ledger" aria-labelledby="status-ledger-title">
      <header><div><h2 id="status-ledger-title">服务与会话</h2><p>当前监督端依赖及数据同步状态</p></div><DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" /></header>
      <div class="status-ledger__rows">
        <article v-for="item in statusItems" :key="item.label">
          <span class="status-ledger__icon" :class="`status-ledger__icon--${item.tone}`" aria-hidden="true"></span>
          <div><strong>{{ item.label }}</strong><small>{{ item.detail }}</small></div>
          <StatusBadge :label="item.value" :tone="item.tone" />
          <time>{{ item.checkedAt }}</time>
        </article>
      </div>
    </section>
    <section v-if="store.status === 'error' && store.error" class="system-alert" role="alert"><strong>最近一次检查失败</strong><p>{{ store.error }}</p><button type="button" @click="handleRefresh">重新检查</button></section>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import DataFreshness from "../components/DataFreshness.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";
defineOptions({ name: "SystemPage" });
const store = useDashboardStore();
const auth = useAuthStore();
const systemDateTimeFormatter = new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
const statusItems = computed(() => [
  { checkedAt: formatTime(store.health.checkedAt), detail: "核心审计、指标与审批接口", label: "Guard API", tone: stateTone(store.health.api), value: stateLabel(store.health.api) },
  { checkedAt: formatTime(store.health.checkedAt), detail: "审计与审批数据持久化", label: "PostgreSQL", tone: stateTone(store.health.database), value: stateLabel(store.health.database) },
  { checkedAt: formatTime(auth.expiresAt), detail: auth.error ?? "HttpOnly Cookie 会话", label: "浏览器会话", tone: auth.isAuthenticated ? "success" as const : "danger" as const, value: auth.isAuthenticated ? "有效" : "异常" },
  { checkedAt: formatTime(store.lastUpdatedAt), detail: "页面可见时每 10 秒同步", label: "审计轮询", tone: store.status === "ready" ? "success" as const : store.status === "stale" ? "warning" as const : store.status === "error" ? "danger" as const : "neutral" as const, value: store.status === "ready" ? "实时" : store.status === "stale" ? "陈旧" : store.status === "error" ? "异常" : "同步中" },
  { checkedAt: "当前配置", detail: "当前 Dashboard 数据连接", label: "数据源", tone: "neutral" as const, value: store.dataSourceMode === "api" ? "Guard API" : "本地场景" },
  { checkedAt: formatTime(store.lastUpdatedAt), detail: "允许一次或拒绝的人工决策", label: "审批队列", tone: store.pendingCount ? "warning" as const : "success" as const, value: `${store.pendingCount} 待处理` },
]);
function stateLabel(value: "online" | "offline" | "unknown") { return value === "online" ? "正常" : value === "offline" ? "异常" : "未知"; }
function stateTone(value: "online" | "offline" | "unknown") { return value === "online" ? "success" as const : value === "offline" ? "danger" as const : "neutral" as const; }
function formatTime(value: string | null) { return value ? systemDateTimeFormatter.format(new Date(value)) : "尚未记录"; }
function handleRefresh() { void store.refresh(); }
</script>

<style scoped lang="scss">
.system-page { display: grid; gap: var(--space-6); }
.status-ledger { border-block: 1px solid var(--color-border); display: grid; }
.status-ledger > header { align-items: center; border-bottom: 1px solid var(--color-border); display: flex; justify-content: space-between; padding: var(--space-4) 0; }
.status-ledger h2, .status-ledger p { margin: 0; }
.status-ledger p { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.status-ledger__rows article { align-items: center; border-bottom: 1px solid var(--color-border); display: grid; gap: var(--space-4); grid-template-columns: .75rem minmax(12rem, 1fr) 6rem 9rem; min-height: 4.75rem; padding: var(--space-3) var(--space-2); }
.status-ledger__rows article:last-child { border-bottom: 0; }
.status-ledger__rows article:hover { background: var(--color-row-hover); }
.status-ledger__icon { background: var(--color-text-subtle); border-radius: 50%; height: .625rem; width: .625rem; }
.status-ledger__icon--success { background: var(--color-success); box-shadow: 0 0 0 4px var(--color-success-soft); }
.status-ledger__icon--warning { background: var(--color-warning); box-shadow: 0 0 0 4px var(--color-warning-soft); }
.status-ledger__icon--danger { background: var(--color-danger); box-shadow: 0 0 0 4px var(--color-danger-soft); }
.status-ledger strong, .status-ledger small { display: block; }
.status-ledger small, .status-ledger time { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.system-alert { align-items: center; background: var(--color-danger-soft); border-left: 3px solid var(--color-danger); display: grid; gap: var(--space-2); grid-template-columns: 1fr auto; padding: var(--space-4); }
.system-alert p { color: var(--color-text-muted); margin: 0; }
.system-alert button { background: var(--color-surface); border: 1px solid var(--color-danger-border); border-radius: var(--radius-2); grid-column: 2; grid-row: 1 / 3; min-height: 2.25rem; padding: 0 var(--space-3); }
@media (max-width: 640px) { .status-ledger > header { align-items: start; flex-direction: column; gap: var(--space-3); } .status-ledger__rows article { grid-template-columns: .75rem minmax(0, 1fr) auto; } .status-ledger time { grid-column: 2 / -1; } }
</style>
