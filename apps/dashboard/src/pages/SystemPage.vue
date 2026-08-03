<template>
  <section class="system-page workspace-panel" aria-labelledby="system-title">
    <header class="page-header">
      <div><h1 id="system-title">系统状态</h1></div>
      <div class="system-header__actions">
        <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
        <button
          class="page-action"
          type="button"
          :aria-busy="store.isManualRefreshing"
          :disabled="store.isManualRefreshing"
          @click="handleRefresh"
        >
          <RefreshCw
            aria-hidden="true"
            :class="{ 'is-spinning': store.isManualRefreshing }"
            :size="15"
          />
          {{ store.isManualRefreshing ? "检查中…" : "立即检查" }}
        </button>
      </div>
    </header>

    <section class="status-ledger" aria-labelledby="status-ledger-title">
      <header>
        <div>
          <h2 id="status-ledger-title">服务与会话</h2>
          <p>当前监督端依赖及数据同步状态</p>
        </div>
        <span>{{ statusItems.length }} 项状态</span>
      </header>
      <div class="status-ledger__rows">
        <article v-for="item in statusItems" :key="item.label">
          <span class="status-dot" :class="`status-dot--${item.tone}`" aria-hidden="true"></span>
          <div>
            <strong>{{ item.label }}</strong
            ><small>{{ item.detail }}</small>
          </div>
          <StatusBadge :label="item.value" :tone="item.tone" /><time
            :datetime="item.checkedAtIso ?? undefined"
            >{{ item.checkedAt }}</time
          >
        </article>
      </div>
    </section>

    <InlineNotice
      v-if="store.status === 'error' && store.error"
      title="最近一次检查失败"
      tone="danger"
    >
      <p>{{ store.error }}</p>
      <template #action><button type="button" @click="handleRefresh">重新检查</button></template>
    </InlineNotice>

    <section class="policy-ledger" aria-labelledby="policy-ledger-title">
      <header>
        <div>
          <h2 id="policy-ledger-title">策略状态</h2>
          <p>查看当前生效的风险判断配置</p>
        </div>
      </header>
      <InlineNotice v-if="store.policyError" title="策略数据加载失败" tone="warning">
        <p>{{ store.policyError }}</p>
        <template #action><button type="button" @click="handleRefresh">重新检查</button></template>
      </InlineNotice>
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
      <InlineNotice v-else-if="store.auditIntegrityError" title="完整性状态暂不可用" tone="warning">
        <p>{{ store.auditIntegrityError }}</p>
        <template #action><button type="button" @click="handleRefresh">重新检查</button></template>
      </InlineNotice>
      <EmptyState v-else title="暂无完整性数据" message="审计完整性信息正在读取。" />
    </section>

    <section class="system-ledger" aria-labelledby="openclaw-verify-title">
      <header>
        <div>
          <h2 id="openclaw-verify-title">OpenClaw 插件验证</h2>
          <p>最近一次验证或心跳上报状态</p>
        </div>
        <StatusBadge :label="adapterStatusLabel" :tone="adapterStatusTone" />
      </header>
      <InlineNotice v-if="store.openclawStatusError" title="OpenClaw 状态加载失败" tone="warning">
        <p>{{ store.openclawStatusError }}</p>
        <template #action><button type="button" @click="handleRefresh">重新检查</button></template>
      </InlineNotice>
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
        <div class="hook-coverage">
          <span><i :style="{ transform: `scaleX(${hookCoverageRatio})` }"></i></span>
          <small>已上报 Hook 覆盖 {{ hookCoverageText }}</small>
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
        <InlineNotice v-if="store.openclawStatus.error" title="适配器报告异常" tone="danger">
          <p>{{ store.openclawStatus.error }}</p>
        </InlineNotice>
        <div v-if="store.openclawStatus.hooks.length" class="hook-list" aria-label="OpenClaw hooks">
          <span v-for="hook in store.openclawStatus.hooks" :key="hook">{{ hook }}</span>
        </div>
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
      <InlineNotice v-if="store.configAuditError" title="发现项加载失败" tone="warning">
        <p>{{ store.configAuditError }}</p>
        <template #action><button type="button" @click="handleRefresh">重新检查</button></template>
      </InlineNotice>
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
import { RefreshCw } from "@lucide/vue";
import { computed } from "vue";
import DataFreshness from "../components/common/DataFreshness.vue";
import EmptyState from "../components/common/EmptyState.vue";
import InlineNotice from "../components/common/InlineNotice.vue";
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
    checkedAtIso: store.health.checkedAt,
    detail: "核心审计、指标与审批接口",
    label: "Guard API",
    tone: stateTone(store.health.api),
    value: stateLabel(store.health.api),
  },
  {
    checkedAt: formatTime(store.health.checkedAt),
    checkedAtIso: store.health.checkedAt,
    detail: "审计与审批数据持久化",
    label: "PostgreSQL",
    tone: stateTone(store.health.database),
    value: stateLabel(store.health.database),
  },
  {
    checkedAt: formatTime(auth.expiresAt),
    checkedAtIso: auth.expiresAt,
    detail: auth.error ?? "HttpOnly Cookie 会话",
    label: "浏览器会话",
    tone: auth.isAuthenticated ? ("success" as const) : ("danger" as const),
    value: auth.isAuthenticated ? "有效" : "异常",
  },
  {
    checkedAt: formatTime(store.lastUpdatedAt),
    checkedAtIso: store.lastUpdatedAt,
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
    checkedAt: formatTime(store.lastUpdatedAt),
    checkedAtIso: store.lastUpdatedAt,
    detail: "仅本次放行或拒绝授权",
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
const hookCoverageRatio = computed(() => {
  const count = store.openclawStatus.hookCount;
  const expected = store.openclawStatus.expectedHookCount;
  if (count === null || expected <= 0) return 0;
  return Math.min(1, Math.max(0, count / expected));
});
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
.system-header__actions {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.system-header__actions button:disabled {
  cursor: wait;
  opacity: 0.65;
}
.is-spinning {
  animation: system-spin 0.8s linear infinite;
}
@keyframes system-spin {
  to {
    transform: rotate(360deg);
  }
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
.status-ledger > header > span {
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
.policy-ledger,
.system-ledger {
  border-top: 1px solid var(--color-border);
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
  background: var(--gradient-active-row), var(--color-surface-muted);
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
.hook-coverage {
  align-items: center;
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(12rem, 1fr) auto;
}
.hook-coverage > span {
  background: var(--color-surface-inset);
  height: 0.45rem;
  overflow: hidden;
}
.hook-coverage i {
  background: var(--gradient-data-active);
  box-shadow: var(--glow-live);
  display: block;
  height: 100%;
  transform-origin: left center;
  transition: transform var(--transition-data);
  width: 100%;
}
.hook-coverage small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
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
  border-top: 1px solid var(--color-border);
  display: grid;
}
.finding-list article {
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  padding: var(--space-5) var(--space-2);
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
</style>
