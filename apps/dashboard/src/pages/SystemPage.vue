<template>
  <section class="system-page workspace-panel" aria-labelledby="system-title">
    <header class="page-header">
      <div><h1 id="system-title">系统状态</h1></div>
      <button
        class="page-action"
        type="button"
        :aria-busy="store.isRefreshing"
        :disabled="store.isRefreshing"
        @click="handleRefresh"
      >
        {{ store.isRefreshing ? "检查中" : "立即检查" }}
      </button>
    </header>

    <section class="status-ledger" aria-labelledby="status-ledger-title">
      <header>
        <div>
          <h2 id="status-ledger-title">服务与会话</h2>
          <p>当前监督端依赖及数据同步状态</p>
        </div>
        <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
      </header>
      <div class="status-ledger__rows">
        <article v-for="item in statusItems" :key="item.label">
          <span class="status-dot" :class="`status-dot--${item.tone}`" aria-hidden="true"></span>
          <div>
            <strong>{{ item.label }}</strong
            ><small>{{ item.detail }}</small>
          </div>
          <StatusBadge :label="item.value" :tone="item.tone" /><time>{{ item.checkedAt }}</time>
        </article>
      </div>
    </section>

    <section v-if="store.status === 'error' && store.error" class="system-alert" role="alert">
      <strong>最近一次检查失败</strong>
      <p>{{ store.error }}</p>
      <button type="button" @click="handleRefresh">重新检查</button>
    </section>

    <section class="policy-ledger" aria-labelledby="policy-ledger-title">
      <header>
        <div>
          <h2 id="policy-ledger-title">策略状态</h2>
          <p>查看当前生效的风险判断配置</p>
        </div>
      </header>
      <section v-if="store.policyError" class="system-alert" role="alert">
        <strong>策略数据加载失败</strong>
        <p>{{ store.policyError }}</p>
        <button type="button" @click="handleRefresh">重新检查</button>
      </section>
      <template v-else-if="store.policySummary">
        <dl class="policy-summary">
          <div>
            <dt>策略包</dt>
            <dd>{{ store.policySummary.bundleId }}</dd>
          </div>
          <div>
            <dt>版本</dt>
            <dd>{{ store.policySummary.version }}</dd>
          </div>
          <div>
            <dt>修订号</dt>
            <dd>{{ store.policySummary.revision ?? "未提供" }}</dd>
          </div>
          <div>
            <dt>更新时间</dt>
            <dd>{{ formatTime(store.policySummary.updatedAt) }}</dd>
          </div>
          <div>
            <dt>停用判断</dt>
            <dd>{{ store.policySummary.disabledRuleCount }}</dd>
          </div>
          <div>
            <dt>自定义判断</dt>
            <dd>{{ store.policySummary.ruleOverrideCount }}</dd>
          </div>
          <div>
            <dt>工具画像</dt>
            <dd>{{ store.policySummary.toolProfileCount }}</dd>
          </div>
        </dl> </template
      ><EmptyState v-else title="暂无策略状态" message="当前没有可展示的策略数据。" />
    </section>

    <section id="audit-integrity" class="system-ledger" aria-labelledby="integrity-title">
      <header>
        <div>
          <h2 id="integrity-title">审计链完整性</h2>
          <p>审计事件哈希链验证状态</p>
        </div>
      </header>
      <template v-if="store.auditIntegrity">
        <div class="integrity-status">
          <span
            class="status-dot"
            :class="`status-dot--${store.auditIntegrity.valid ? 'success' : 'danger'}`"
            aria-hidden="true"
          ></span>
          <StatusBadge
            :label="store.auditIntegrity.valid ? '审计链有效' : '审计链异常'"
            :tone="store.auditIntegrity.valid ? 'success' : 'danger'"
          />
          <span class="integrity-count">{{ store.auditIntegrity.eventCount }} 条审计事件</span>
        </div>
        <dl class="integrity-detail">
          <div>
            <dt>链头哈希</dt>
            <dd>
              <code class="hash-short">{{
                formatAuditHeadHash(store.auditIntegrity.headHash)
              }}</code>
            </dd>
          </div>
          <div v-if="store.auditIntegrity.firstBrokenAuditId">
            <dt>首个异常审计</dt>
            <dd>
              <RouterLink :to="`/investigations?search=${store.auditIntegrity.firstBrokenAuditId}`">
                {{ store.auditIntegrity.firstBrokenAuditId }}
              </RouterLink>
            </dd>
          </div>
        </dl>
      </template>
      <EmptyState v-else title="暂无完整性数据" message="审计完整性信息加载中或不可用。" />
    </section>

    <section class="system-ledger" aria-labelledby="openclaw-verify-title">
      <header>
        <div>
          <h2 id="openclaw-verify-title">OpenClaw 插件验证</h2>
          <p>最近一次验证或心跳上报状态</p>
        </div>
        <StatusBadge :label="adapterStatusLabel" :tone="adapterStatusTone" />
      </header>
      <section v-if="store.openclawStatusError" class="system-alert" role="alert">
        <strong>OpenClaw 状态加载失败</strong>
        <p>{{ store.openclawStatusError }}</p>
        <button type="button" @click="handleRefresh">重新检查</button>
      </section>
      <div class="adapter-verify">
        <div class="adapter-verify__headline">
          <span
            class="status-dot"
            :class="`status-dot--${adapterStatusTone}`"
            aria-hidden="true"
          ></span>
          <div>
            <strong>插件验证</strong>
            <span>{{ store.openclawStatus.runtimeVersion ?? "运行时版本未记录" }}</span>
          </div>
          <b>{{ hookCoverageText }}</b>
        </div>
        <dl class="adapter-verify__facts">
          <div>
            <dt>Hook 覆盖</dt>
            <dd>{{ hookCoverageText }}</dd>
          </div>
          <div>
            <dt>最近验证</dt>
            <dd>{{ formatTime(store.openclawStatus.lastVerifiedAt) }}</dd>
          </div>
          <div>
            <dt>最近心跳</dt>
            <dd>{{ formatTime(store.openclawStatus.lastHeartbeatAt) }}</dd>
          </div>
          <div>
            <dt>来源</dt>
            <dd>{{ store.openclawStatus.source ?? "未提供" }}</dd>
          </div>
          <div>
            <dt>插件版本</dt>
            <dd>{{ store.openclawStatus.pluginVersion ?? "未提供" }}</dd>
          </div>
          <div>
            <dt>失败关闭阶段</dt>
            <dd>{{ store.openclawStatus.failClosedStages.length }} 阶段</dd>
          </div>
        </dl>
        <p v-if="store.openclawStatus.error" class="adapter-verify__error">
          {{ store.openclawStatus.error }}
        </p>
        <div v-if="store.openclawStatus.hooks.length" class="hook-list" aria-label="OpenClaw hooks">
          <span v-for="hook in store.openclawStatus.hooks" :key="hook">{{ hook }}</span>
        </div>
      </div>
    </section>

    <section class="system-ledger" aria-labelledby="adapters-title">
      <header>
        <div>
          <h2 id="adapters-title">运行时审计活动</h2>
          <p>按已加载审计事件统计运行时写入情况</p>
        </div>
      </header>
      <div class="adapter-grid">
        <article class="adapter-card">
          <h3>LangGraph</h3>
          <dl>
            <div>
              <dt>审计事件</dt>
              <dd>{{ langgraphStats.count }}</dd>
            </div>
            <div>
              <dt>阻断数</dt>
              <dd>{{ langgraphStats.blocked }}</dd>
            </div>
            <div>
              <dt>最近活动</dt>
              <dd>{{ langgraphStats.lastSeen ?? "暂无记录" }}</dd>
            </div>
          </dl>
          <RouterLink
            v-if="langgraphStats.count > 0"
            class="page-action adapter-card__link"
            to="/investigations?runtime=langgraph"
          >
            查看事件
          </RouterLink>
        </article>
        <article class="adapter-card">
          <h3>OpenClaw</h3>
          <dl>
            <div>
              <dt>审计事件</dt>
              <dd>{{ openclawStats.count }}</dd>
            </div>
            <div>
              <dt>阻断数</dt>
              <dd>{{ openclawStats.blocked }}</dd>
            </div>
            <div>
              <dt>最近活动</dt>
              <dd>{{ openclawStats.lastSeen ?? "暂无记录" }}</dd>
            </div>
          </dl>
          <RouterLink
            v-if="openclawStats.count > 0"
            class="page-action adapter-card__link"
            to="/investigations?runtime=openclaw"
          >
            查看事件
          </RouterLink>
        </article>
      </div>
    </section>

    <section class="system-ledger" aria-labelledby="config-audit-title">
      <header>
        <div>
          <h2 id="config-audit-title">配置审计发现项</h2>
          <p>后端保存的配置检查发现项</p>
        </div>
        <div class="finding-summary" aria-label="发现项严重性摘要">
          <span v-for="item in findingSummary" :key="item.label"
            >{{ item.label }} {{ item.value }}</span
          >
        </div>
      </header>
      <section v-if="store.configAuditError" class="system-alert" role="alert">
        <strong>发现项加载失败</strong>
        <p>{{ store.configAuditError }}</p>
        <button type="button" @click="handleRefresh">重新检查</button>
      </section>
      <div v-if="store.configAuditFindings.length" class="finding-list">
        <article v-for="row in store.configAuditFindings" :key="row.finding.findingId">
          <header>
            <StatusBadge
              :label="getRiskSeverityLabel(row.finding.severity)"
              :tone="getRiskSeverityTone(row.finding.severity)"
            />
            <strong>{{ row.finding.title }}</strong>
          </header>
          <dl>
            <div>
              <dt>目标</dt>
              <dd>{{ row.targetType }} / {{ row.targetId }}</dd>
            </div>
            <div>
              <dt>主体</dt>
              <dd>{{ row.finding.subject }}</dd>
            </div>
            <div>
              <dt>运行时</dt>
              <dd>{{ row.runtime }}</dd>
            </div>
            <div>
              <dt>时间</dt>
              <dd>{{ formatTime(row.timestamp) }}</dd>
            </div>
          </dl>
          <p>{{ row.finding.description }}</p>
          <p v-if="row.finding.recommendation" class="finding-list__recommendation">
            {{ row.finding.recommendation }}
          </p>
          <details v-if="row.finding.evidence?.length" class="finding-list__evidence">
            <summary>证据 ({{ row.finding.evidence.length }})</summary>
            <ul>
              <li v-for="(e, i) in row.finding.evidence" :key="i">{{ e }}</li>
            </ul>
          </details>
          <div class="finding-list__links">
            <RouterLink :to="`/evidence/${row.traceId}`">{{ row.traceId }}</RouterLink>
            <RouterLink :to="`/investigations?event_id=${row.eventId}`">
              {{ row.eventId }}
            </RouterLink>
          </div>
        </article>
      </div>
      <EmptyState
        v-else
        title="暂无配置审计发现项"
        message="配置审计结果写入后将在这里展示发现项明细。"
      />
    </section>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import StatusBadge from "../components/common/StatusBadge.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";
import {
  formatAuditHeadHash,
  getRiskSeverityLabel,
  getRiskSeverityTone,
  type StatusBadgeTone,
} from "../utils/dashboard-formatters";

defineOptions({ name: "SystemPage" });

const store = useDashboardStore();
const auth = useAuthStore();
const systemDateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});

const statusItems = computed(() => [
  {
    checkedAt: formatTime(store.health.checkedAt),
    detail: "核心审计、指标与审批接口",
    label: "Guard API",
    tone: stateTone(store.health.api),
    value: stateLabel(store.health.api),
  },
  {
    checkedAt: formatTime(store.health.checkedAt),
    detail: "审计与审批数据持久化",
    label: "PostgreSQL",
    tone: stateTone(store.health.database),
    value: stateLabel(store.health.database),
  },
  {
    checkedAt: formatTime(auth.expiresAt),
    detail: auth.error ?? "HttpOnly Cookie 会话",
    label: "浏览器会话",
    tone: auth.isAuthenticated ? ("success" as const) : ("danger" as const),
    value: auth.isAuthenticated ? "有效" : "异常",
  },
  {
    checkedAt: formatTime(store.lastUpdatedAt),
    detail: "页面可见时每 10 秒同步",
    label: "审计轮询",
    tone:
      store.status === "ready"
        ? ("success" as const)
        : store.status === "stale"
          ? ("warning" as const)
          : store.status === "error"
            ? ("danger" as const)
            : ("neutral" as const),
    value:
      store.status === "ready"
        ? "实时"
        : store.status === "stale"
          ? "陈旧"
          : store.status === "error"
            ? "异常"
            : "同步中",
  },
  {
    checkedAt: "当前配置",
    detail: "当前 Dashboard 数据连接",
    label: "数据源",
    tone: "neutral" as const,
    value: store.dataSourceMode === "api" ? "Guard API" : "本地场景",
  },
  {
    checkedAt: formatTime(store.lastUpdatedAt),
    detail: "仅本次放行或拒绝并阻断",
    label: "审批队列",
    tone: store.pendingCount ? ("warning" as const) : ("success" as const),
    value: `${store.pendingCount} 待处理`,
  },
]);

const adapterStatusTone = computed<StatusBadgeTone>(() => {
  if (store.openclawStatus.status === "loaded" && store.openclawStatus.loaded) return "success";
  if (store.openclawStatus.status === "error") return "danger";
  if (store.openclawStatus.status === "not_loaded") return "warning";
  return "neutral";
});
const adapterStatusLabel = computed(() => {
  if (store.openclawStatus.status === "loaded" && store.openclawStatus.loaded) return "已加载";
  if (store.openclawStatus.status === "error") return "异常";
  if (store.openclawStatus.status === "not_loaded") return "未加载";
  return "未知";
});
const hookCoverageText = computed(() =>
  store.openclawStatus.hookCount === null
    ? `-- / ${store.openclawStatus.expectedHookCount}`
    : `${store.openclawStatus.hookCount} / ${store.openclawStatus.expectedHookCount}`,
);
const findingSummary = computed(() => {
  const labels = [
    ["严重", "critical"],
    ["高", "high"],
    ["中", "medium"],
    ["低", "low"],
  ] as const;
  return labels.map(([label, severity]) => ({
    label,
    value: store.configAuditFindings.filter((row) => row.finding.severity === severity).length,
  }));
});

function runtimeStats(runtime: string) {
  const events = store.events.filter((event) => event.runtime === runtime);
  const last = events.reduce<string | null>(
    (value, event) => (!value || event.occurredAt > value ? event.occurredAt : value),
    null,
  );
  return {
    count: events.length,
    blocked: events.filter((event) => event.blocked).length,
    lastSeen: last ? systemDateTimeFormatter.format(new Date(last)) : null,
  };
}

const langgraphStats = computed(() => runtimeStats("langgraph"));
const openclawStats = computed(() => runtimeStats("openclaw"));

function stateLabel(value: "online" | "offline" | "unknown") {
  return value === "online" ? "正常" : value === "offline" ? "异常" : "未知";
}

function stateTone(value: "online" | "offline" | "unknown"): StatusBadgeTone {
  return value === "online" ? "success" : value === "offline" ? "danger" : "neutral";
}

function formatTime(value: string | null) {
  if (!value) return "尚未记录";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : systemDateTimeFormatter.format(date);
}

function handleRefresh() {
  void store.refresh();
}
</script>

<style scoped lang="scss">
.system-page {
  display: grid;
  gap: var(--space-6);
}
.status-ledger {
  border-block: 1px solid var(--color-border);
  display: grid;
}
.status-ledger > header {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  display: flex;
  justify-content: space-between;
  padding: var(--space-4) 0;
}
.status-ledger h2,
.status-ledger p {
  margin: 0;
}
.status-ledger p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.status-ledger__rows article {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  grid-template-columns: 0.75rem minmax(12rem, 1fr) 6rem 9rem;
  min-height: 4.75rem;
  padding: var(--space-3) var(--space-2);
}
.status-ledger__rows article:last-child {
  border-bottom: 0;
}
.status-ledger__rows article:hover {
  background: var(--color-row-hover);
}
.status-ledger strong,
.status-ledger small {
  display: block;
}
.status-ledger small,
.status-ledger time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.status-dot {
  background: var(--color-text-subtle);
  border-radius: 50%;
  height: 0.625rem;
  width: 0.625rem;
}
.status-dot--success {
  background: var(--color-success);
  box-shadow: 0 0 0 4px var(--color-success-soft);
}
.status-dot--warning {
  background: var(--color-warning);
  box-shadow: 0 0 0 4px var(--color-warning-soft);
}
.status-dot--danger {
  background: var(--color-danger);
  box-shadow: 0 0 0 4px var(--color-danger-soft);
}
.system-alert {
  align-items: center;
  background: var(--color-danger-soft);
  border-left: 3px solid var(--color-danger);
  display: grid;
  gap: var(--space-2);
  grid-template-columns: 1fr auto;
  padding: var(--space-4);
}
.system-alert p {
  color: var(--color-text-muted);
  margin: 0;
}
.system-alert button {
  background: var(--color-surface);
  border: 1px solid var(--color-danger-border);
  border-radius: var(--radius-2);
  grid-column: 2;
  grid-row: 1 / 3;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}
.policy-ledger,
.system-ledger {
  border-block: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  padding: var(--space-5) 0;
}
.policy-ledger > header h2,
.policy-ledger > header p,
.system-ledger h2,
.system-ledger p {
  margin: 0;
}
.policy-ledger > header p,
.system-ledger > header > div > p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin-top: var(--space-1);
}
.system-ledger > header {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-4);
  justify-content: space-between;
}
.policy-summary,
.integrity-detail,
.adapter-verify__facts {
  display: grid;
  gap: 1px;
  grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
  margin: 0;
  overflow: hidden;
}
.policy-summary > div,
.integrity-detail > div,
.adapter-verify__facts > div {
  background: var(--color-surface-muted);
  display: grid;
  gap: var(--space-1);
  min-width: 0;
  padding: var(--space-3);
}
.policy-summary dt,
.integrity-detail dt,
.adapter-verify__facts dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.policy-summary dd,
.integrity-detail dd,
.adapter-verify__facts dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.integrity-status {
  align-items: center;
  display: flex;
  gap: var(--space-3);
}
.integrity-count {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
}
.hash-short {
  font-size: var(--font-size-12);
}
.adapter-verify {
  display: grid;
  gap: var(--space-4);
}
.adapter-verify__headline {
  align-items: center;
  background: linear-gradient(90deg, var(--color-active-soft), var(--color-surface-muted));
  border: 1px solid var(--color-active-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 0.75rem minmax(0, 1fr) auto;
  padding: var(--space-4);
}
.adapter-verify__headline div {
  display: grid;
  gap: var(--space-1);
  min-width: 0;
}
.adapter-verify__headline span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-13);
  overflow-wrap: anywhere;
}
.adapter-verify__headline b {
  color: var(--color-active);
  font-size: var(--font-size-24);
  font-variant-numeric: tabular-nums;
}
.adapter-verify__error {
  background: var(--color-danger-soft);
  border-left: 3px solid var(--color-danger);
  color: var(--color-danger);
  padding: var(--space-3);
}
.hook-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}
.hook-list span {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  padding: 0.2rem 0.45rem;
}
.adapter-grid {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 18rem), 1fr));
}
.adapter-card {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-3);
  padding: var(--space-4);
}
.adapter-card h3 {
  font-size: var(--font-size-14);
  margin: 0;
}
.adapter-card dl {
  display: grid;
  gap: var(--space-2);
  grid-template-columns: 1fr 1fr 1fr;
  margin: 0;
}
.adapter-card dl > div {
  display: grid;
  gap: var(--space-1);
}
.adapter-card dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.adapter-card dd {
  font-size: var(--font-size-16);
  font-weight: var(--font-weight-semibold);
  margin: 0;
}
.adapter-card__link {
  justify-self: start;
}
.finding-summary {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}
.finding-summary span {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  font-size: var(--font-size-12);
  padding: 0.25rem 0.5rem;
}
.finding-list {
  display: grid;
  gap: var(--space-3);
}
.finding-list article {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-3);
  padding: var(--space-4);
}
.finding-list article > header {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.finding-list article > header strong {
  overflow-wrap: anywhere;
}
.finding-list dl {
  display: grid;
  gap: var(--space-3);
  grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
  margin: 0;
}
.finding-list dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.finding-list dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.finding-list p {
  color: var(--color-text-muted);
  font-size: var(--font-size-13);
  margin: 0;
  overflow-wrap: anywhere;
}
.finding-list__recommendation {
  color: var(--color-text) !important;
}
.finding-list__links {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.finding-list__evidence {
  border-top: 1px solid var(--color-border);
  padding-top: var(--space-2);
}
.finding-list__evidence summary {
  color: var(--color-text-subtle);
  cursor: pointer;
  font-size: var(--font-size-12);
  user-select: none;
}
.finding-list__evidence ul {
  list-style: disc;
  margin: var(--space-2) 0 0 var(--space-4);
  padding: 0;
}
.finding-list__evidence li {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  overflow-wrap: anywhere;
}
@media (max-width: 640px) {
  .status-ledger > header {
    align-items: start;
    flex-direction: column;
    gap: var(--space-3);
  }
  .status-ledger__rows article {
    grid-template-columns: 0.75rem minmax(0, 1fr) auto;
  }
  .status-ledger time {
    grid-column: 2 / -1;
  }
  .adapter-verify__headline {
    grid-template-columns: 0.75rem minmax(0, 1fr);
  }
  .adapter-verify__headline b {
    grid-column: 2;
  }
  .adapter-card dl {
    grid-template-columns: 1fr;
  }
}
</style>
