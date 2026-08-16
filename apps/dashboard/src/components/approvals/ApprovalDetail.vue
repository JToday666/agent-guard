<template>
  <div class="approval-detail">
    <header class="approval-detail__header">
      <div>
        <p>审批请求</p>
        <h2>{{ approval.actionName }}</h2>
      </div>
      <div class="risk-score" :class="`risk-score--${approval.severity}`">
        <strong>{{ approval.riskScore }}</strong
        ><small>/ 100</small>
        <span class="risk-score__label">{{ getRiskSeverityLabel(approval.severity) }}</span>
      </div>
    </header>

    <div class="approval-detail__body">
      <section class="approval-context" aria-label="审批上下文">
        <div>
          <h3>用户任务</h3>
          <p>{{ approval.userTask || "未提供" }}</p>
        </div>
        <div>
          <h3>智能体请求执行的动作</h3>
          <p>{{ approval.agentAction || "未提供" }}</p>
        </div>
      </section>

      <dl class="evidence-grid">
        <div>
          <dt>动作名称</dt>
          <dd>
            <code>{{ approval.actionName }}</code>
          </dd>
        </div>
        <div>
          <dt>目标资源</dt>
          <dd>
            <code>{{ approval.resource }}</code>
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
          <h3>命中规则</h3>
          <div v-if="approval.ruleHits.length" class="approval-rule-list">
            <span v-for="rule in approval.ruleHits" :key="rule">{{ ruleLabel(rule) }}</span>
          </div>
          <p v-else>未命中阻断规则</p>
        </div>
        <div>
          <h3>判定原因</h3>
          <p>{{ approval.reason }}</p>
        </div>
      </section>

      <section class="impact-callout">
        <strong>放行影响</strong>
        <p>{{ approval.consequence }}</p>
        <p>
          “仅本次放行”只授权当前审批精确关联的动作与资源；原始 official ASK
          不会被改写，且不代表动作已经开始或执行成功。
        </p>
      </section>

      <nav class="evidence-links" aria-label="关联证据">
        <RouterLink v-if="approvalRoutes" :to="approvalRoutes.trace">查看完整证据链</RouterLink>
        <RouterLink v-if="approvalRoutes?.event" :to="approvalRoutes.event">
          定位关联事件
        </RouterLink>
        <span v-else class="evidence-links__unavailable">未提供事件定位信息</span>
        <span class="evidence-links__ids">
          事件 <code>{{ evidenceFields.eventId }}</code> · 证据链
          <code>{{ evidenceFields.traceId }}</code>
        </span>
      </nav>
    </div>

    <footer class="approval-actions">
      <span v-if="actionMessage" role="status">{{ actionMessage }}</span>
      <span v-else-if="resolutionDisabledReason" class="approval-disabled-reason">{{
        resolutionDisabledReason
      }}</span>
      <button
        v-if="supportsDecision('allow_once')"
        type="button"
        class="button-warning"
        :disabled="!canResolveDecision('allow_once')"
        :title="resolutionDisabledReason"
        @click="confirmationDecision = 'allow_once'"
      >
        {{ submittingDecision === "allow_once" ? "提交中…" : "仅本次放行" }}
      </button>
      <button
        v-if="supportsDecision('deny')"
        type="button"
        class="button-danger"
        :disabled="!canResolveDecision('deny')"
        :title="resolutionDisabledReason"
        @click="confirmationDecision = 'deny'"
      >
        {{ submittingDecision === "deny" ? "提交中…" : "拒绝授权" }}
      </button>
    </footer>

    <ConfirmDialog
      v-if="confirmationDecision && confirmationContent"
      :busy-label="confirmationContent.busyLabel"
      :confirm-label="confirmationContent.confirmLabel"
      :confirm-disabled="!canResolveDecision(confirmationDecision)"
      :error-message="actionMessage"
      :eyebrow="confirmationContent.eyebrow"
      :is-submitting="submittingDecision === confirmationDecision"
      :title="confirmationContent.title"
      :tone="confirmationContent.tone"
      @close="confirmationDecision = null"
      @confirm="handleConfirm"
    >
      <p>{{ confirmationContent.description }}</p>
      <dl class="confirm-impact">
        <div>
          <dt>动作名称</dt>
          <dd>
            <code>{{ approval.actionName }}</code>
          </dd>
        </div>
        <div>
          <dt>目标资源</dt>
          <dd>
            <code>{{ approval.resource }}</code>
          </dd>
        </div>
        <div>
          <dt>{{ confirmationContent.impactLabel }}</dt>
          <dd>{{ confirmationImpact }}</dd>
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
import { ruleLabel } from "../../utils/rule-display";
import ConfirmDialog from "../common/ConfirmDialog.vue";

const props = defineProps<{
  approval: ApprovalRequest;
  approvalRoutes: { trace: RouteLocationRaw; event?: RouteLocationRaw | null } | null;
  canResolveDecision: (decision: ConfirmationDecision) => boolean;
  submittingDecision: "allow_once" | "deny" | null;
  actionMessage: string;
  resolutionDisabledReason: string;
}>();

const emit = defineEmits<{ resolve: [decision: "allow_once" | "deny"] }>();

type ConfirmationDecision = "allow_once" | "deny";

const confirmationDecision = ref<ConfirmationDecision | null>(null);
const confirmationContent = computed(() => {
  if (confirmationDecision.value === "allow_once") {
    return {
      busyLabel: "正在放行…",
      confirmLabel: "确认仅本次放行",
      description:
        "这只会授权当前审批精确关联的动作与资源；原始 official ASK 保持不变，是否开始或成功仍以运行时门禁与回执为准。",
      eyebrow: "高影响操作",
      impactLabel: "放行影响",
      title: "确认仅本次放行？",
      tone: "warning" as const,
    };
  }
  if (confirmationDecision.value === "deny") {
    return {
      busyLabel: "正在拒绝…",
      confirmLabel: "确认拒绝授权",
      description: "本次授权将被拒绝；实际执行状态仍以运行时回执为准。",
      eyebrow: "拒绝授权",
      impactLabel: "处理结果",
      title: "确认拒绝本次授权？",
      tone: "danger" as const,
    };
  }
  return null;
});
const confirmationImpact = computed(() =>
  confirmationDecision.value === "deny"
    ? "拒绝本次授权；运行时是否产生其他结果，以后续审计记录为准。"
    : "仅授权当前审批精确关联的动作与资源一次；不表示动作已开始或执行成功。",
);

function supportsDecision(decision: ConfirmationDecision): boolean {
  return props.approval.decisionOptions.includes(decision);
}

watch(
  () => props.approval.id,
  () => {
    confirmationDecision.value = null;
  },
);

watch(
  () => props.approval.decisionOptions,
  () => {
    if (confirmationDecision.value && !supportsDecision(confirmationDecision.value)) {
      confirmationDecision.value = null;
    }
  },
);

const evidenceFields = computed(() => formatApprovalEvidenceFields(props.approval));

function handleConfirm(): void {
  if (
    confirmationDecision.value &&
    supportsDecision(confirmationDecision.value) &&
    props.canResolveDecision(confirmationDecision.value)
  ) {
    emit("resolve", confirmationDecision.value);
  }
}
</script>

<style scoped lang="scss">
.approval-detail {
  container-name: approval-detail;
  container-type: inline-size;
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
}
.approval-detail__header h2 {
  font-size: var(--font-size-24);
  margin-top: var(--space-1);
  overflow-wrap: anywhere;
}
.risk-score {
  align-items: flex-end;
  background: var(--color-surface-muted);
  border-left: 3px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  display: flex;
  flex: 0 0 auto;
  flex-direction: column;
  gap: var(--space-1);
  padding: var(--space-3) var(--space-4);
  text-align: right;
}
.risk-score strong {
  color: var(--color-text-muted);
  font-size: clamp(1.5rem, 4vw, 2rem);
  line-height: 1;
}
.risk-score small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.risk-score__label {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  letter-spacing: 0.04em;
}
.risk-score--critical,
.risk-score--high {
  background: var(--color-danger-soft);
  border-left-color: var(--color-danger);
}
.risk-score--critical strong,
.risk-score--critical .risk-score__label,
.risk-score--high strong,
.risk-score--high .risk-score__label {
  color: var(--color-danger);
}
.risk-score--medium {
  background: var(--color-warning-soft);
  border-left-color: var(--color-warning);
}
.risk-score--medium strong,
.risk-score--medium .risk-score__label {
  color: var(--color-warning);
}
.approval-detail__body {
  align-content: start;
  display: grid;
  gap: var(--space-5);
  grid-auto-rows: max-content;
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
.approval-context,
.approval-evidence {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  padding-top: var(--space-4);
}
.approval-context h3,
.approval-evidence h3 {
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
  letter-spacing: 0.06em;
  margin: 0;
  text-transform: uppercase;
}
.approval-context p,
.approval-evidence p {
  color: var(--color-text-muted);
  margin: var(--space-1) 0 0;
  overflow-wrap: anywhere;
}
.approval-rule-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin-top: var(--space-2);
}
.approval-rule-list span {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-1);
  color: var(--color-text);
  font-size: var(--font-size-12);
  padding: var(--space-1) var(--space-2);
}
.evidence-links {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}
.evidence-links a {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  display: inline-flex;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
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
.evidence-links__ids {
  color: var(--color-text-subtle);
  flex-basis: 100%;
  font-size: var(--font-size-11);
  overflow-wrap: anywhere;
}
.approval-actions {
  align-items: center;
  background: color-mix(in srgb, var(--color-page) 88%, transparent);
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
  min-height: 2.75rem;
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
.button-danger {
  background: var(--color-danger);
  border-color: var(--color-danger) !important;
  color: var(--color-active-text);
  font-weight: var(--font-weight-bold);
}
.button-warning:hover:not(:disabled),
.button-danger:hover:not(:disabled) {
  transform: translateY(-1px);
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
@container approval-detail (max-width: 44rem) {
  .evidence-grid {
    grid-template-columns: 1fr;
  }
}
</style>
