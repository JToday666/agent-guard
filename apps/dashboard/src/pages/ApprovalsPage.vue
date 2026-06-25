<template>
  <section class="approvals-page workspace-panel" aria-labelledby="approvals-title">
    <header class="page-header">
      <div><p>人工控制</p><h1 id="approvals-title">审批中心</h1></div>
      <div class="approval-header-status">
        <DataFreshness :status="store.status" :updated-at="store.lastUpdatedAt" />
        <StatusBadge :label="`${store.pendingCount} 待处理`" :tone="store.pendingCount ? 'warning' : 'success'" />
      </div>
    </header>

    <ErrorState v-if="store.status === 'error' && store.error" :is-retrying="store.isRefreshing" :message="store.error" @retry="store.refresh" />
    <LoadingState v-else-if="store.status === 'loading' && !store.approvals.length" />
    <div v-else-if="sortedApprovals.length" class="approvals-layout">
      <aside class="approval-queue" aria-label="待审批队列">
        <header><div><strong>风险队列</strong><small>高风险与临近过期优先</small></div></header>
        <button
          v-for="approval in sortedApprovals"
          :key="approval.id"
          type="button"
          :class="{ 'approval-queue__item--active': selectedApproval?.id === approval.id }"
          @click="handleSelectApproval(approval)"
        >
          <span class="approval-queue__top">
            <StatusBadge :label="getRiskSeverityLabel(approval.severity)" :tone="getRiskSeverityTone(approval.severity)" />
            <time>{{ formatRelativeExpiry(approval.expiresAt) }}</time>
          </span>
          <strong>{{ approval.tool }}</strong>
          <small>{{ approval.resource }}</small>
          <span class="approval-queue__score">风险 {{ approval.riskScore }}</span>
        </button>
      </aside>

      <article v-if="selectedApproval" class="approval-detail">
        <header class="approval-detail__header">
          <div><p>审批请求</p><h2>{{ selectedApproval.tool }}</h2></div>
          <strong class="approval-detail__risk">{{ selectedApproval.riskScore }}<small>/ 100</small></strong>
        </header>

        <section class="impact-callout">
          <strong>放行影响</strong>
          <p>{{ selectedApproval.consequence }}</p>
        </section>

        <dl class="evidence-grid">
          <div><dt>目标资源</dt><dd><code>{{ selectedApproval.resource }}</code></dd></div>
          <div><dt>风险等级</dt><dd>{{ getRiskSeverityLabel(selectedApproval.severity) }}</dd></div>
          <div><dt>请求时间</dt><dd>{{ formatDashboardDateTime(selectedApproval.createdAt) }}</dd></div>
          <div><dt>到期时间</dt><dd>{{ selectedApproval.expiresAt ? formatDashboardDateTime(selectedApproval.expiresAt) : "未提供" }}</dd></div>
        </dl>

        <section class="approval-evidence">
          <div><h3>判定原因</h3><p>{{ selectedApproval.reason }}</p></div>
          <div><h3>用户任务</h3><p>{{ selectedApproval.userTask || "未提供" }}</p></div>
          <div><h3>Agent 行为</h3><p>{{ selectedApproval.agentAction || "未提供" }}</p></div>
        </section>

        <nav class="evidence-links" aria-label="关联证据">
          <RouterLink v-if="selectedApprovalRoutes" :to="selectedApprovalRoutes.trace">查看完整 Trace</RouterLink>
          <RouterLink v-if="selectedApprovalRoutes?.event" :to="selectedApprovalRoutes.event">定位关联事件</RouterLink>
          <span v-else class="evidence-links__unavailable">未提供事件定位信息</span>
        </nav>

        <section v-if="confirmAllow" class="allow-confirm" role="alertdialog" aria-labelledby="allow-confirm-title">
          <div><strong id="allow-confirm-title">确认允许一次？</strong><p>将继续执行 {{ selectedApproval.tool }}，目标为 {{ selectedApproval.resource }}。</p></div>
          <button type="button" @click="confirmAllow = false">取消</button>
          <button type="button" class="button-warning" :disabled="!canResolveApproval" @click="handleResolveApproval('allow_once')">确认允许</button>
        </section>

        <footer class="approval-actions">
          <span v-if="actionMessage" role="status">{{ actionMessage }}</span>
          <span v-else-if="resolutionDisabledReason" class="approval-disabled-reason">{{ resolutionDisabledReason }}</span>
          <button type="button" class="button-secondary" :disabled="!canResolveApproval" :title="resolutionDisabledReason" @click="confirmAllow = true">允许一次</button>
          <button type="button" class="button-danger" :disabled="!canResolveApproval" :title="resolutionDisabledReason" @click="handleResolveApproval('deny')">
            {{ isSubmitting ? "提交中..." : "拒绝并阻断" }}
          </button>
        </footer>
      </article>
    </div>
    <EmptyState v-else title="审批队列已清空" message="当前没有等待人工处理的工具动作。">
      <RouterLink to="/investigations">查看调查事件</RouterLink>
    </EmptyState>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import DataFreshness from "../components/DataFreshness.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/States/ErrorState.vue";
import LoadingState from "../components/States/LoadingState.vue";
import { useAuthStore } from "../stores/authStore";
import { useDashboardStore } from "../stores/dashboardStore";
import type { ApprovalRequest } from "../types/dashboard";
import { getApprovalEvidenceRoutes } from "../utils/approval-evidence-route";
import {
  formatDashboardDateTime,
  getRiskSeverityLabel,
  getRiskSeverityTone,
} from "../utils/dashboard-formatters";

defineOptions({ name: "ApprovalsPage" });
const store = useDashboardStore();
const authStore = useAuthStore();
const route = useRoute();
const router = useRouter();
const confirmAllow = ref(false);
const actionMessage = ref("");
const sortedApprovals = computed(() => [...store.approvals].sort((left, right) => {
  if (left.riskScore !== right.riskScore) return right.riskScore - left.riskScore;
  return Date.parse(left.expiresAt ?? left.createdAt) - Date.parse(right.expiresAt ?? right.createdAt);
}));
const requestedId = computed(() => typeof route.params.approval_id === "string" ? route.params.approval_id : "");
const selectedApproval = computed(() => requestedId.value
  ? sortedApprovals.value.find((approval) => approval.id === requestedId.value) ?? sortedApprovals.value[0]
  : sortedApprovals.value[0]);
const selectedApprovalRoutes = computed(() => selectedApproval.value
  ? getApprovalEvidenceRoutes(selectedApproval.value)
  : null);
const isSubmitting = computed(() => store.submittingApprovalId === selectedApproval.value?.id);
const isExpired = computed(() => {
  const expiresAt = selectedApproval.value?.expiresAt;
  return Boolean(expiresAt && Date.parse(expiresAt) <= Date.now());
});
const resolutionDisabledReason = computed(() => {
  if (isSubmitting.value) return "审批正在提交";
  if (!authStore.csrfToken) return "浏览器会话未就绪，缺少 CSRF token";
  if (!selectedApproval.value?.approvalNonce) return "审批凭证缺失，请刷新队列";
  if (isExpired.value) return "审批已过期，不能继续处理";
  return "";
});
const canResolveApproval = computed(() => Boolean(selectedApproval.value) && !resolutionDisabledReason.value);
const approvalIds = computed(() => sortedApprovals.value.map((approval) => approval.id).join("\u0000"));
watch([requestedId, approvalIds, () => store.status], () => {
  if (route.name !== "approvals") return;
  if (store.status === "idle" || store.status === "loading") return;
  const firstApprovalId = sortedApprovals.value[0]?.id;
  if (!firstApprovalId) {
    if (requestedId.value) void router.replace("/approvals");
    return;
  }
  if (requestedId.value && !store.approvals.some((approval) => approval.id === requestedId.value)) {
    void router.replace(`/approvals/${firstApprovalId}`);
  }
}, { immediate: true });
watch(() => selectedApproval.value?.id, () => { confirmAllow.value = false; actionMessage.value = ""; });

function handleSelectApproval(approval: ApprovalRequest) { void router.push(`/approvals/${approval.id}`); }
async function handleResolveApproval(decision: "allow_once" | "deny") {
  if (!selectedApproval.value || !canResolveApproval.value) return;
  const id = selectedApproval.value.id;
  try {
    await store.resolveApproval(selectedApproval.value, decision);
    actionMessage.value = decision === "deny" ? "已拒绝该动作" : "已允许该动作执行一次";
    confirmAllow.value = false;
    if (!store.approvals.some((approval) => approval.id === id)) void router.replace("/approvals");
  } catch {
    actionMessage.value = store.error ?? "审批提交失败";
  }
}
function formatRelativeExpiry(value?: string | null) {
  if (!value) return "到期时间未知";
  const minutes = Math.ceil((Date.parse(value) - Date.now()) / 60_000);
  return minutes <= 0 ? "已过期" : `${minutes} 分钟后过期`;
}
</script>

<style scoped lang="scss">
.approvals-page { display: grid; gap: var(--space-5); }
.approval-header-status { align-items: center; display: flex; flex-wrap: wrap; gap: var(--space-3); }
.approvals-layout { display: grid; gap: var(--space-4); grid-template-columns: minmax(17rem, 21rem) minmax(0, 1fr); }
.approval-queue { align-content: start; border-right: 1px solid var(--color-border); display: grid; gap: 0; padding-right: var(--space-4); }
.approval-queue > header { padding: var(--space-2); }
.approval-queue > header small { color: var(--color-text-subtle); display: block; margin-top: var(--space-1); }
.approval-queue > button { background: transparent; border: 0; border-bottom: 1px solid var(--color-border); color: var(--color-text); cursor: pointer; display: grid; gap: var(--space-2); min-width: 0; padding: var(--space-4) var(--space-3); text-align: left; }
.approval-queue > button:hover { background: var(--color-row-hover); }
.approval-queue > button.approval-queue__item--active { background: var(--color-danger-soft); box-shadow: inset 3px 0 var(--color-danger); }
.approval-queue__top { align-items: center; display: flex; justify-content: space-between; }
.approval-queue__top time, .approval-queue > button small { color: var(--color-text-subtle); font-size: var(--font-size-11); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.approval-queue__score { color: var(--color-danger); font-size: var(--font-size-12); font-weight: var(--font-weight-bold); }
.approval-detail { align-content: start; display: grid; gap: var(--space-5); min-width: 0; }
.approval-detail__header { align-items: start; display: flex; justify-content: space-between; }
.approval-detail__header p, .approval-detail__header h2 { margin: 0; }
.approval-detail__header p { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.approval-detail__header h2 { font-size: var(--font-size-24); margin-top: var(--space-1); }
.approval-detail__risk { color: var(--color-danger); font-size: 2rem; line-height: 1; }
.approval-detail__risk small { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.impact-callout { background: var(--color-warning-soft); border: 1px solid var(--color-warning-border); border-radius: var(--radius-2); padding: var(--space-4); }
.impact-callout p { color: var(--color-text-muted); margin: var(--space-1) 0 0; }
.evidence-grid { display: grid; gap: 1px; grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 0; overflow: hidden; }
.evidence-grid > div { background: var(--color-surface-muted); padding: var(--space-3); }
.evidence-grid dt { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.evidence-grid dd { margin: var(--space-1) 0 0; overflow-wrap: anywhere; }
.approval-evidence { border-top: 1px solid var(--color-border); display: grid; gap: var(--space-4); padding-top: var(--space-4); }
.approval-evidence h3 { font-size: var(--font-size-13); margin: 0; }
.approval-evidence p { color: var(--color-text-muted); margin: var(--space-1) 0 0; }
.evidence-links { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.evidence-links a { background: var(--color-surface-muted); border: 1px solid var(--color-border); border-radius: var(--radius-2); color: var(--color-text); padding: var(--space-2) var(--space-3); text-decoration: none; }
.evidence-links__unavailable { align-self: center; color: var(--color-text-subtle); font-size: var(--font-size-12); }
.allow-confirm { align-items: center; background: var(--color-warning-soft); border: 1px solid var(--color-warning-border); border-radius: var(--radius-2); display: grid; gap: var(--space-3); grid-template-columns: 1fr auto auto; padding: var(--space-3); }
.allow-confirm p { color: var(--color-text-muted); margin: var(--space-1) 0 0; }
.allow-confirm button, .approval-actions button { border: 1px solid var(--color-border); border-radius: var(--radius-2); cursor: pointer; min-height: 2.5rem; padding: 0 var(--space-4); }
.approval-actions { align-items: center; background: rgb(244 247 251 / .94); border-top: 1px solid var(--color-border); bottom: 0; display: flex; gap: var(--space-3); justify-content: flex-end; margin-inline: calc(-1 * var(--space-2)); padding: var(--space-4) var(--space-2); position: sticky; }
.approval-actions span { color: var(--color-text-muted); margin-right: auto; }
.approval-disabled-reason { color: var(--color-warning) !important; font-size: var(--font-size-12); }
.approval-actions button:disabled, .allow-confirm button:disabled { cursor: not-allowed; opacity: 0.55; }
.button-secondary { background: var(--color-surface-muted); color: var(--color-text); }
.button-warning { background: var(--color-warning); border-color: var(--color-warning) !important; color: var(--color-active-text); }
.button-danger { background: var(--color-danger); border-color: var(--color-danger) !important; color: var(--color-active-text); font-weight: var(--font-weight-bold); }
@media (max-width: 820px) { .approvals-layout { grid-template-columns: 1fr; } .approval-queue { border-bottom: 1px solid var(--color-border); border-right: 0; max-height: 20rem; overflow: auto; padding: 0 0 var(--space-4); } }
@media (max-width: 600px) { .evidence-grid { grid-template-columns: 1fr; } .allow-confirm { grid-template-columns: 1fr 1fr; } .allow-confirm > div { grid-column: 1 / -1; } .approval-actions { align-items: stretch; flex-direction: column; } .approval-actions span { margin: 0; } }
</style>
