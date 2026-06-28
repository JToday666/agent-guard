<template>
  <section class="system-page workspace-panel" aria-labelledby="system-title">
    <header class="page-header"><div><h1 id="system-title">系统状态</h1></div><button class="page-action" type="button" :aria-busy="store.isRefreshing" :disabled="store.isRefreshing" @click="handleRefresh">{{ store.isRefreshing ? "检查中" : "立即检查" }}</button></header>
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
    <section class="policy-ledger" aria-labelledby="policy-ledger-title">
      <header><div><h2 id="policy-ledger-title">策略状态</h2><p>查看当前生效的风险判断配置</p></div></header>
      <section v-if="store.policyError" class="system-alert" role="alert"><strong>策略数据加载失败</strong><p>{{ store.policyError }}</p><button type="button" @click="handleRefresh">重新检查</button></section>
      <template v-else-if="store.policySummary">
        <dl class="policy-summary">
          <div><dt>策略包</dt><dd>{{ store.policySummary.bundleId }}</dd></div>
          <div><dt>版本</dt><dd>{{ store.policySummary.version }}</dd></div>
          <div><dt>修订号</dt><dd>{{ store.policySummary.revision ?? "未提供" }}</dd></div>
          <div><dt>更新时间</dt><dd>{{ formatTime(store.policySummary.updatedAt) }}</dd></div>
          <div><dt>停用判断</dt><dd>{{ store.policySummary.disabledRuleCount }}</dd></div>
          <div><dt>自定义判断</dt><dd>{{ store.policySummary.ruleOverrideCount }}</dd></div>
          <div><dt>工具画像</dt><dd>{{ store.policySummary.toolProfileCount }}</dd></div>
        </dl>
        <div v-if="store.policyHistory.length" class="policy-history" role="list" aria-label="策略历史">
          <article v-for="item in store.policyHistory.slice(0, 5)" :key="item.revision" role="listitem">
            <strong>修订 {{ item.revision }}</strong><span>{{ item.bundleId }} / {{ item.version }}</span><time>{{ formatTime(item.updatedAt) }}</time><small>{{ item.updatedBy }}</small>
          </article>
        </div>
      </template>
      <EmptyState v-else title="暂无策略状态" message="当前没有可展示的策略数据。" />
    </section>

    <section id="audit-integrity" class="system-ledger" aria-labelledby="integrity-title">
      <header><div><h2 id="integrity-title">审计链完整性</h2><p>审计事件哈希链验证状态</p></div></header>
      <template v-if="store.auditIntegrity">
        <div class="integrity-status">
          <span class="status-ledger__icon" :class="`status-ledger__icon--${store.auditIntegrity.valid ? 'success' : 'danger'}`" aria-hidden="true"></span>
          <StatusBadge :label="store.auditIntegrity.valid ? '审计链有效' : '审计链异常'" :tone="store.auditIntegrity.valid ? 'success' : 'danger'" />
          <span class="integrity-count">{{ store.auditIntegrity.eventCount }} 条审计事件</span>
        </div>
        <dl class="integrity-detail">
          <div><dt>链头哈希</dt><dd><code class="hash-short">{{ store.auditIntegrity.headHash.slice(0, 12) }}…</code></dd></div>
          <div v-if="store.auditIntegrity.firstBrokenAuditId"><dt>首个异常审计</dt><dd><RouterLink :to="`/investigations?search=${store.auditIntegrity.firstBrokenAuditId}`">{{ store.auditIntegrity.firstBrokenAuditId }}</RouterLink></dd></div>
        </dl>
      </template>
      <EmptyState v-else title="暂无完整性数据" message="审计完整性信息加载中或不可用。" />
    </section>

    <section class="system-ledger" aria-labelledby="adapters-title">
      <header><div><h2 id="adapters-title">运行时适配器</h2><p>查看哪些运行时正在写入审计事件</p></div></header>
      <div class="adapter-grid">
        <article class="adapter-card">
          <h3>LangGraph</h3>
          <dl>
            <div><dt>审计事件</dt><dd>{{ langraphStats.count }}</dd></div>
            <div><dt>阻断数</dt><dd>{{ langraphStats.blocked }}</dd></div>
            <div><dt>最近活动</dt><dd>{{ langraphStats.lastSeen ?? "暂无记录" }}</dd></div>
          </dl>
          <RouterLink v-if="langraphStats.count > 0" class="page-action adapter-card__link" to="/investigations?runtime=langgraph">查看事件</RouterLink>
        </article>
        <article class="adapter-card">
          <h3>OpenClaw</h3>
          <dl>
            <div><dt>审计事件</dt><dd>{{ openclawStats.count }}</dd></div>
            <div><dt>阻断数</dt><dd>{{ openclawStats.blocked }}</dd></div>
            <div><dt>最近活动</dt><dd>{{ openclawStats.lastSeen ?? "暂无记录" }}</dd></div>
          </dl>
          <RouterLink v-if="openclawStats.count > 0" class="page-action adapter-card__link" to="/investigations?runtime=openclaw">查看事件</RouterLink>
        </article>
      </div>
    </section>

    <!-- 配置审计摘要 -->
    <section class="system-ledger" aria-labelledby="config-audit-title">
      <header><div><h2 id="config-audit-title">配置审计</h2><p>查看配置检查发现的风险项</p></div><RouterLink class="page-action" to="/investigations?event_type=config_audit">查看全部</RouterLink></header>
      <template v-if="configAuditEvents.length">
        <div class="event-table-wrap">
          <table class="event-table">
            <caption>配置审计事件</caption>
            <thead><tr><th>时间</th><th>目标类型</th><th>目标 ID</th><th>决策</th><th>发现数</th></tr></thead>
            <tbody>
              <tr v-for="evt in configAuditEvents.slice(0, 5)" :key="evt.id">
                <td><time>{{ evt.time }}</time></td>
                <td>{{ getRawMeta(evt, 'target_type') ?? "—" }}</td>
                <td class="truncate-cell">{{ getRawMeta(evt, 'target_id') ?? "—" }}</td>
                <td><StatusBadge :label="getDecisionLabel(evt.decision)" :tone="getDecisionTone(evt.decision)" /></td>
                <td>{{ getRawMeta(evt, 'finding_count') ?? "—" }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
      <EmptyState v-else title="暂无配置审计事件" message="配置审计结果将在运行后自动写入审计事件。" />
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import DataFreshness from "../components/DataFreshness.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";
import type { AuditEventRow } from "../types/dashboard";
import { getDecisionLabel, getDecisionTone } from "../utils/dashboard-formatters";
defineOptions({ name: "SystemPage" });
const store = useDashboardStore();
const auth = useAuthStore();

function getRawMeta(evt: AuditEventRow, key: string): unknown {
  const raw = evt.raw as { metadata?: Record<string, unknown> } | null;
  return raw?.metadata?.[key];
}
const systemDateTimeFormatter = new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
const statusItems = computed(() => [
  { checkedAt: formatTime(store.health.checkedAt), detail: "核心审计、指标与审批接口", label: "Guard API", tone: stateTone(store.health.api), value: stateLabel(store.health.api) },
  { checkedAt: formatTime(store.health.checkedAt), detail: "审计与审批数据持久化", label: "PostgreSQL", tone: stateTone(store.health.database), value: stateLabel(store.health.database) },
  { checkedAt: formatTime(auth.expiresAt), detail: auth.error ?? "HttpOnly Cookie 会话", label: "浏览器会话", tone: auth.isAuthenticated ? "success" as const : "danger" as const, value: auth.isAuthenticated ? "有效" : "异常" },
  { checkedAt: formatTime(store.lastUpdatedAt), detail: "页面可见时每 10 秒同步", label: "审计轮询", tone: store.status === "ready" ? "success" as const : store.status === "stale" ? "warning" as const : store.status === "error" ? "danger" as const : "neutral" as const, value: store.status === "ready" ? "实时" : store.status === "stale" ? "陈旧" : store.status === "error" ? "异常" : "同步中" },
  { checkedAt: "当前配置", detail: "当前 Dashboard 数据连接", label: "数据源", tone: "neutral" as const, value: store.dataSourceMode === "api" ? "Guard API" : "本地场景" },
  { checkedAt: formatTime(store.lastUpdatedAt), detail: "允许一次或拒绝的人工决策", label: "审批队列", tone: store.pendingCount ? "warning" as const : "success" as const, value: `${store.pendingCount} 待处理` },
]);

function runtimeStats(runtime: string) {
  const evts = store.events.filter((e) => e.runtime === runtime);
  const last = evts.reduce<string | null>((m, e) => (!m || e.occurredAt > m ? e.occurredAt : m), null);
  return {
    count: evts.length,
    blocked: evts.filter((e) => e.blocked).length,
    lastSeen: last ? systemDateTimeFormatter.format(new Date(last)) : null,
  };
}

const langraphStats = computed(() => runtimeStats("langgraph"));
const openclawStats = computed(() => runtimeStats("openclaw"));
const configAuditEvents = computed(() => store.events.filter((e) => e.eventType === "config_audit").slice(0, 5));

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
.policy-ledger { border-block: 1px solid var(--color-border); display: grid; gap: var(--space-4); padding: var(--space-4) 0; }
.policy-ledger > header h2, .policy-ledger > header p { margin: 0; }
.policy-ledger > header p { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.policy-summary { display: grid; gap: 1px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 0; overflow: hidden; }
.policy-summary > div { background: var(--color-surface-muted); display: grid; gap: var(--space-1); min-width: 0; padding: var(--space-3); }
.policy-summary dt { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.policy-summary dd { margin: 0; overflow-wrap: anywhere; }
.policy-history { display: grid; }
.policy-history article { align-items: center; border-bottom: 1px solid var(--color-border); display: grid; gap: var(--space-3); grid-template-columns: minmax(8rem, .6fr) minmax(0, 1fr) 9rem 7rem; min-height: 3.25rem; padding: 0 var(--space-2); }
.policy-history article:last-child { border-bottom: 0; }
.policy-history span, .policy-history time, .policy-history small { color: var(--color-text-subtle); font-size: var(--font-size-12); overflow-wrap: anywhere; }
@media (max-width: 640px) { .status-ledger > header { align-items: start; flex-direction: column; gap: var(--space-3); } .status-ledger__rows article { grid-template-columns: .75rem minmax(0, 1fr) auto; } .status-ledger time { grid-column: 2 / -1; } }
@media (max-width: 760px) { .policy-summary { grid-template-columns: 1fr 1fr; } .policy-history article { grid-template-columns: 1fr auto; padding: var(--space-3) 0; } .policy-history span { grid-column: 1 / -1; } }
.system-ledger { border-block: 1px solid var(--color-border); display: grid; gap: var(--space-4); padding: var(--space-5) 0; }
.system-ledger > header { align-items: center; display: flex; gap: var(--space-4); justify-content: space-between; flex-wrap: wrap; }
.system-ledger h2, .system-ledger p { margin: 0; }
.system-ledger > header > div > p { color: var(--color-text-subtle); font-size: var(--font-size-12); margin-top: var(--space-1); }
.integrity-status { align-items: center; display: flex; gap: var(--space-3); }
.integrity-count { color: var(--color-text-subtle); font-size: var(--font-size-13); }
.integrity-detail { display: grid; gap: var(--space-3); grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); margin: 0; }
.integrity-detail > div { background: var(--color-surface-muted); display: grid; gap: var(--space-1); padding: var(--space-3); }
.integrity-detail dt { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.integrity-detail dd { margin: 0; }
.hash-short { font-size: var(--font-size-12); }
.adapter-grid { display: grid; gap: var(--space-4); grid-template-columns: repeat(auto-fit, minmax(min(100%, 18rem), 1fr)); }
.adapter-card { background: var(--color-surface-muted); border: 1px solid var(--color-border); border-radius: var(--radius-2); display: grid; gap: var(--space-3); padding: var(--space-4); }
.adapter-card h3 { font-size: var(--font-size-14); margin: 0; }
.adapter-card dl { display: grid; gap: var(--space-2); grid-template-columns: 1fr 1fr 1fr; margin: 0; }
.adapter-card dl > div { display: grid; gap: var(--space-1); }
.adapter-card dt { color: var(--color-text-subtle); font-size: var(--font-size-11); }
.adapter-card dd { font-size: var(--font-size-16); font-weight: var(--font-weight-semibold); margin: 0; }
.adapter-card__link { justify-self: start; }
.event-table-wrap { overflow: auto; }
.event-table { border-collapse: collapse; min-width: 38rem; width: 100%; }
.event-table caption { clip: rect(0,0,0,0); height: 1px; overflow: hidden; position: absolute; width: 1px; }
.event-table th, .event-table td { border-bottom: 1px solid var(--color-border); font-size: var(--font-size-13); padding: var(--space-3); text-align: left; vertical-align: middle; }
.event-table th { color: var(--color-text-subtle); font-size: var(--font-size-11); letter-spacing: .03em; text-transform: uppercase; }
</style>
