<template>
  <div class="approval-detail">
    <header class="approval-detail__header">
      <div>
        <p>审批请求</p>
        <h2>{{ approval.tool }}</h2>
      </div>
      <div class="risk-score-card">
        <strong>{{ approval.riskScore }}</strong
        ><small>/ 100</small>
        <span class="risk-score-card__label">{{ getRiskSeverityLabel(approval.severity) }}</span>
      </div>
    </header>

    <div class="approval-detail__body">
      <section class="impact-callout">
        <strong>放行影响</strong>
        <p>{{ approval.consequence }}</p>
      </section>

      <dl class="evidence-grid">
        <div>
          <dt>目标资源</dt>
          <dd>
            <code>{{ approval.resource }}</code>
          </dd>
        </div>
        <div>
          <dt>关联事件</dt>
          <dd>
            <code>{{ evidenceFields.eventId }}</code>
          </dd>
        </div>
        <div>
          <dt>证据链</dt>
          <dd>
            <code>{{ evidenceFields.traceId }}</code>
          </dd>
        </div>
        <div>
          <dt>审批主体</dt>
          <dd>
            <code>{{ evidenceFields.subject }}</code>
          </dd>
        </div>
        <div>
          <dt>动作</dt>
          <dd>
            <code>{{ evidenceFields.action }}</code>
          </dd>
        </div>
        <div>
          <dt>风险等级</dt>
          <dd>{{ getRiskSeverityLabel(approval.severity) }}</dd>
        </div>
        <div>
          <dt>请求时间</dt>
          <dd>{{ formatDashboardDateTime(approval.createdAt) }}</dd>
        </div>
        <div>
          <dt>到期时间</dt>
          <dd>{{ approval.expiresAt ? formatDashboardDateTime(approval.expiresAt) : "未提供" }}</dd>
        </div>
      </dl>

      <section class="approval-evidence">
        <div>
          <h3>判定原因</h3>
          <p>{{ approval.reason }}</p>
        </div>
        <div>
          <h3>用户任务</h3>
          <p>{{ approval.userTask || "未提供" }}</p>
        </div>
        <div>
          <h3>Agent 行为</h3>
          <p>{{ approval.agentAction || "未提供" }}</p>
        </div>
      </section>

      <nav class="evidence-links" aria-label="关联证据">
        <RouterLink v-if="approvalRoutes" :to="approvalRoutes.trace">查看完整证据链</RouterLink>
        <RouterLink v-if="approvalRoutes?.event" :to="approvalRoutes.event">
          定位关联事件
        </RouterLink>
        <span v-else class="evidence-links__unavailable">未提供事件定位信息</span>
      </nav>
    </div>

    <footer class="approval-actions">
      <span v-if="actionMessage" role="status">{{ actionMessage }}</span>
      <span v-else-if="resolutionDisabledReason" class="approval-disabled-reason">{{
        resolutionDisabledReason
      }}</span>
      <button
        type="button"
        class="button-warning"
        :disabled="!canResolve"
        :title="resolutionDisabledReason"
        @click="confirmAllow = true"
      >
        仅本次放行
      </button>
      <button
        type="button"
        class="button-primary"
        :disabled="!canResolve"
        :title="resolutionDisabledReason"
        @click="emit('resolve', 'deny')"
      >
        {{ submittingDecision === "deny" ? "提交中…" : "拒绝并阻断" }}
      </button>
    </footer>

    <ConfirmDialog
      v-if="confirmAllow"
      busy-label="正在放行…"
      confirm-label="确认仅本次放行"
      :confirm-disabled="!canResolve"
      :error-message="actionMessage"
      eyebrow="高影响操作"
      :is-submitting="submittingDecision === 'allow_once'"
      title="确认仅本次放行？"
      tone="warning"
      @close="confirmAllow = false"
      @confirm="emit('resolve', 'allow_once')"
    >
      <p>该动作将绕过当前 Guard 决策并继续执行一次。</p>
      <dl class="confirm-impact">
        <div>
          <dt>工具</dt>
          <dd>
            <code>{{ approval.tool }}</code>
          </dd>
        </div>
        <div>
          <dt>目标资源</dt>
          <dd>
            <code>{{ approval.resource }}</code>
          </dd>
        </div>
        <div>
          <dt>放行影响</dt>
          <dd>{{ approval.consequence }}</dd>
        </div>
      </dl>
    </ConfirmDialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { RouteLocationRaw } from "vue-router";
import { formatApprovalEvidenceFields } from "../../data/approvals/evidence";
import type { ApprovalRequest } from "../../types/dashboard";
import { formatDashboardDateTime, getRiskSeverityLabel } from "../../utils/dashboard-formatters";
import ConfirmDialog from "../common/ConfirmDialog.vue";

const props = defineProps<{
  approval: ApprovalRequest;
  approvalRoutes: { trace: RouteLocationRaw; event?: RouteLocationRaw | null } | null;
  canResolve: boolean;
  submittingDecision: "allow_once" | "deny" | null;
  actionMessage: string;
  resolutionDisabledReason: string;
}>();

const emit = defineEmits<{ resolve: [decision: "allow_once" | "deny"] }>();

const confirmAllow = ref(false);

watch(
  () => props.approval.id,
  () => {
    confirmAllow.value = false;
  },
);

const evidenceFields = computed(() => formatApprovalEvidenceFields(props.approval));
</script>

<style scoped lang="scss">
.approval-detail {
  display: grid;
  gap: var(--space-4);
  grid-template-rows: auto minmax(0, 1fr) auto;
  height: 100%;
  min-height: 0;
  min-width: 0;
  overflow: hidden;
}
.approval-detail__header {
  align-items: start;
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
  min-width: 0;
}
.approval-detail__header p,
.approval-detail__header h2 {
  margin: 0;
}
.approval-detail__header p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.approval-detail__header h2 {
  font-size: var(--font-size-24);
  margin-top: var(--space-1);
  overflow-wrap: anywhere;
}
.risk-score-card {
  align-items: flex-end;
  background: var(--color-danger-soft);
  border-left: 3px solid var(--color-danger);
  border-radius: var(--radius-2);
  display: flex;
  flex: 0 0 auto;
  flex-direction: column;
  gap: var(--space-1);
  padding: var(--space-3) var(--space-4);
  text-align: right;
}
.risk-score-card strong {
  color: var(--color-danger);
  font-size: clamp(1.5rem, 4vw, 2rem);
  line-height: 1;
}
.risk-score-card small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.risk-score-card__label {
  color: var(--color-danger);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.approval-detail__body {
  align-content: start;
  display: grid;
  gap: var(--space-5);
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  padding-right: var(--space-2);
}
.impact-callout {
  background: var(--color-warning-soft);
  border: 1px solid var(--color-warning-border);
  border-radius: var(--radius-3);
  padding: var(--space-4);
}
.impact-callout p {
  color: var(--color-text-muted);
  margin: var(--space-1) 0 0;
}
.evidence-grid {
  display: grid;
  gap: 1px;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
  overflow: hidden;
}
.evidence-grid > div {
  background: var(--color-surface-muted);
  padding: var(--space-3);
}
.evidence-grid dt {
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.evidence-grid dd {
  color: var(--color-text);
  font-weight: var(--font-weight-semibold);
  margin: var(--space-1) 0 0;
  overflow-wrap: anywhere;
}
.approval-evidence {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  padding-top: var(--space-4);
}
.approval-evidence h3 {
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
  letter-spacing: 0.06em;
  margin: 0;
  text-transform: uppercase;
}
.approval-evidence p {
  color: var(--color-text-muted);
  margin: var(--space-1) 0 0;
  overflow-wrap: anywhere;
}
.evidence-links {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}
.evidence-links a {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  padding: var(--space-2) var(--space-3);
  text-decoration: none;
}
.evidence-links a:hover {
  border-color: var(--color-active-border);
  color: var(--color-link);
}
.evidence-links__unavailable {
  align-self: center;
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.approval-actions {
  align-items: center;
  background: var(--color-page);
  border-top: 1px solid var(--color-border);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  justify-content: flex-end;
  padding-top: var(--space-4);
}
.approval-actions span {
  color: var(--color-text-muted);
  margin-right: auto;
}
.approval-disabled-reason {
  color: var(--color-warning) !important;
  font-size: var(--font-size-12);
}
.approval-actions button {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  cursor: pointer;
  min-height: 2.5rem;
  padding: 0 var(--space-4);
}
.approval-actions button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}
.button-warning {
  background: var(--color-warning-soft);
  border-color: var(--color-warning-border) !important;
  color: var(--color-warning);
  font-weight: var(--font-weight-bold);
}
.button-primary {
  background: var(--color-active);
  border-color: var(--color-active) !important;
  color: var(--color-active-text);
  font-weight: var(--font-weight-bold);
}
.confirm-impact {
  display: grid;
  gap: var(--space-3);
  margin: 0;
}
.confirm-impact > div {
  display: grid;
  gap: var(--space-1);
}
.confirm-impact dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.confirm-impact dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.confirm-impact code {
  color: var(--color-text);
}
@media (max-width: 1180px) {
  .evidence-grid {
    grid-template-columns: 1fr;
  }
}
</style>
