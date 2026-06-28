<template>
  <div class="approval-detail">
    <header class="approval-detail__header">
      <div>
        <p>审批请求</p>
        <h2>{{ approval.tool }}</h2>
      </div>
      <div class="risk-score-card">
        <strong>{{ approval.riskScore }}</strong><small>/ 100</small>
        <span class="risk-score-card__label">{{ getRiskSeverityLabel(approval.severity) }}</span>
      </div>
    </header>

    <section class="impact-callout">
      <strong>放行影响</strong>
      <p>{{ approval.consequence }}</p>
    </section>

    <dl class="evidence-grid">
      <div><dt>目标资源</dt><dd><code>{{ approval.resource }}</code></dd></div>
      <div><dt>审批对象</dt><dd><code>{{ subjectLabel }}</code></dd></div>
      <div><dt>动作</dt><dd>{{ approval.actionName ?? approval.tool }}</dd></div>
      <div><dt>风险等级</dt><dd>{{ getRiskSeverityLabel(approval.severity) }}</dd></div>
      <div><dt>请求时间</dt><dd>{{ formatDashboardDateTime(approval.createdAt) }}</dd></div>
      <div><dt>到期时间</dt><dd>{{ approval.expiresAt ? formatDashboardDateTime(approval.expiresAt) : '未提供' }}</dd></div>
    </dl>

    <section class="approval-evidence">
      <div><h3>判定原因</h3><p>{{ approval.reason }}</p></div>
      <div><h3>用户任务</h3><p>{{ approval.userTask || '未提供' }}</p></div>
      <div><h3>Agent 行为</h3><p>{{ approval.agentAction || '未提供' }}</p></div></section>

    <nav class="evidence-links" aria-label="关联证据">
      <RouterLink v-if="approvalRoutes" :to="approvalRoutes.trace">查看完整证据链</RouterLink>
      <RouterLink v-if="approvalRoutes?.event" :to="approvalRoutes.event">定位关联事件</RouterLink>
      <span v-else class="evidence-links__unavailable">未提供事件定位信息</span>
    </nav>

    <section v-if="confirmAllow" class="allow-confirm" role="alertdialog" aria-modal="true" aria-labelledby="allow-confirm-title">
      <div class="allow-confirm__dialog">
        <div>
          <strong id="allow-confirm-title">确认允许一次？</strong>
          <p>将继续执行 {{ approval.tool }}，目标为 {{ approval.resource }}。</p>
        </div>
        <footer>
          <button type="button" @click="confirmAllow = false">取消</button>
          <button type="button" class="button-success" :disabled="!canResolve" @click="emit('resolve', 'allow_once')">确认允许</button>
        </footer>
      </div>
    </section>

    <footer class="approval-actions">
      <span v-if="actionMessage" role="status">{{ actionMessage }}</span>
      <span v-else-if="resolutionDisabledReason" class="approval-disabled-reason">{{ resolutionDisabledReason }}</span>
      <button type="button" class="button-success" :disabled="!canResolve" :title="resolutionDisabledReason" @click="confirmAllow = true">允许一次</button>
      <button type="button" class="button-danger" :disabled="!canResolve" :title="resolutionDisabledReason" @click="emit('resolve', 'deny')">
        {{ isSubmitting ? '提交中...' : '拒绝并阻断' }}
      </button>
    </footer>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { RouteLocationRaw } from "vue-router";
import type { ApprovalRequest } from "../types/dashboard";
import { formatDashboardDateTime, getRiskSeverityLabel } from "../utils/dashboard-formatters";

const props = defineProps<{
  approval: ApprovalRequest;
  approvalRoutes: { trace: RouteLocationRaw; event?: RouteLocationRaw | null } | null;
  canResolve: boolean;
  isSubmitting: boolean;
  actionMessage: string;
  resolutionDisabledReason: string;
}>();

const emit = defineEmits<{ resolve: [decision: "allow_once" | "deny"] }>();

const confirmAllow = ref(false);

watch(() => props.approval.id, () => { confirmAllow.value = false; });

const subjectLabel = computed(() => {
  if (!props.approval.subjectId) return "未提供";
  return `${props.approval.subjectType ?? "subject"} / ${props.approval.subjectId}`;
});
</script>

<style scoped lang="scss">
.approval-detail {
  align-content: start;
  display: grid;
  gap: var(--space-5);
  height: 100%;
  min-height: 0;
  min-width: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  padding-right: var(--space-2);
}
.approval-detail__header { align-items: start; display: flex; gap: var(--space-4); justify-content: space-between; min-width: 0; }
.approval-detail__header p, .approval-detail__header h2 { margin: 0; }
.approval-detail__header p { color: var(--color-text-subtle); font-size: var(--font-size-12); letter-spacing: 0.04em; text-transform: uppercase; }
.approval-detail__header h2 { font-size: var(--font-size-24); margin-top: var(--space-1); overflow-wrap: anywhere; }
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
.risk-score-card strong { color: var(--color-danger); font-size: clamp(1.5rem, 4vw, 2rem); line-height: 1; }
.risk-score-card small { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.risk-score-card__label { color: var(--color-danger); font-size: var(--font-size-12); font-weight: var(--font-weight-semibold); letter-spacing: 0.04em; text-transform: uppercase; }
.impact-callout { background: var(--color-warning-soft); border: 1px solid var(--color-warning-border); border-radius: var(--radius-3); padding: var(--space-4); }
.impact-callout p { color: var(--color-text-muted); margin: var(--space-1) 0 0; }
.evidence-grid { display: grid; gap: 1px; grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 0; overflow: hidden; }
.evidence-grid > div { background: var(--color-surface-muted); padding: var(--space-3); }
.evidence-grid dt { color: var(--color-text-muted); font-size: var(--font-size-11); font-weight: var(--font-weight-semibold); letter-spacing: 0.06em; text-transform: uppercase; }
.evidence-grid dd { color: var(--color-text); font-weight: var(--font-weight-semibold); margin: var(--space-1) 0 0; overflow-wrap: anywhere; }
.approval-evidence { border-top: 1px solid var(--color-border); display: grid; gap: var(--space-4); padding-top: var(--space-4); }
.approval-evidence h3 { font-size: var(--font-size-11); font-weight: var(--font-weight-semibold); letter-spacing: 0.06em; margin: 0; text-transform: uppercase; }
.approval-evidence p { color: var(--color-text-muted); margin: var(--space-1) 0 0; overflow-wrap: anywhere; }
.evidence-links { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.evidence-links a { background: var(--color-surface-muted); border: 1px solid var(--color-border); border-radius: var(--radius-2); color: var(--color-text); padding: var(--space-2) var(--space-3); text-decoration: none; }
.evidence-links a:hover { border-color: var(--color-active-border); color: var(--color-link); }
.evidence-links__unavailable { align-self: center; color: var(--color-text-subtle); font-size: var(--font-size-12); }
.allow-confirm { align-items: center; background: rgb(16 24 40 / 0.38); display: grid; inset: 0; justify-items: center; padding: var(--space-4); position: fixed; z-index: 60; }
.allow-confirm__dialog { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-2); box-shadow: var(--shadow-raised); display: grid; gap: var(--space-4); max-width: 30rem; padding: var(--space-5); width: min(100%, 30rem); }
.allow-confirm__dialog footer { display: flex; gap: var(--space-3); justify-content: flex-end; }
.allow-confirm p { color: var(--color-text-muted); margin: var(--space-1) 0 0; }
.allow-confirm button, .approval-actions button { border: 1px solid var(--color-border); border-radius: var(--radius-2); cursor: pointer; min-height: 2.5rem; padding: 0 var(--space-4); }
.approval-actions { align-items: center; background: rgb(244 247 251 / 0.94); border-top: 1px solid var(--color-border); bottom: 0; display: flex; flex-wrap: wrap; gap: var(--space-3); justify-content: flex-end; padding: var(--space-4) 0; position: sticky; }
.approval-actions span { color: var(--color-text-muted); margin-right: auto; }
.approval-disabled-reason { color: var(--color-warning) !important; font-size: var(--font-size-12); }
.approval-actions button:disabled, .allow-confirm button:disabled { cursor: not-allowed; opacity: 0.55; }
.button-success { background: var(--color-success); border-color: var(--color-success) !important; color: var(--color-active-text); font-weight: var(--font-weight-bold); }
.button-danger { background: var(--color-danger); border-color: var(--color-danger) !important; color: var(--color-active-text); font-weight: var(--font-weight-bold); }
@media (max-width: 640px) {
  .evidence-grid { grid-template-columns: 1fr; }
  .allow-confirm__dialog footer { flex-direction: column-reverse; }
  .approval-actions { align-items: stretch; flex-direction: column; }
  .approval-actions span { margin: 0; }
}
</style>