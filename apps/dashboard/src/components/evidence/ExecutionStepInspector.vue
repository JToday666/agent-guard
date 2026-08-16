<template>
  <aside class="execution-inspector" aria-label="运行步骤详情">
    <template v-if="step">
      <header class="execution-inspector__header">
        <div>
          <span>第 {{ stepNumber }} 步 · {{ getExecutionCategoryLabel(step.category) }}</span>
          <h4>{{ step.displayName }}</h4>
          <code v-if="step.actionName" translate="no">{{ step.actionName }}</code>
        </div>
        <StatusBadge
          :label="getDecisionLabel(step.supervision.officialDecision.decision)"
          :tone="getDecisionTone(step.supervision.officialDecision.decision)"
        />
      </header>

      <div class="execution-inspector__state">
        <strong>{{ displayStatus(step) }}</strong>
        <span>{{ getSemanticsSummary(step.supervision.semantics) }}</span>
      </div>

      <ExecutionSupervisionCapsules v-if="step.kind === 'action'" :step="step" />

      <dl class="execution-inspector__facts">
        <div>
          <dt>动作 / 资源</dt>
          <dd>{{ step.resourceSummary ?? "未记录资源目标" }}</dd>
        </div>
        <div>
          <dt>风险</dt>
          <dd>{{ step.riskScore ?? "未记录" }} · {{ getRiskSeverityLabel(step.severity) }}</dd>
        </div>
        <div>
          <dt>安全判断</dt>
          <dd>{{ step.policyChecks.length }} 次</dd>
        </div>
        <div>
          <dt>最近更新</dt>
          <dd>
            <time :datetime="step.lastUpdatedAt">{{ formatTime(step.lastUpdatedAt) }}</time>
          </dd>
        </div>
      </dl>

      <section class="execution-inspector__section">
        <h5>正式决策 / V2 Shadow</h5>
        <div class="execution-inspector__comparison">
          <article>
            <span>OFFICIAL</span>
            <strong>{{ getDecisionLabel(step.supervision.officialDecision.decision) }}</strong>
            <p>{{ step.supervision.officialDecision.reason ?? "未记录判定原因" }}</p>
            <small>
              {{ getAvailabilityLabel(step.supervision.officialDecision.availability) }} ·
              {{ step.supervision.officialDecision.ruleIds.length }} 条规则
            </small>
          </article>
          <article class="is-shadow">
            <span>V2 SHADOW</span>
            <strong>{{ v21Disposition(step) }}</strong>
            <p>{{ v21Summary(step) }}</p>
            <small>
              {{ getAuthorityLabel(step.supervision.v21Assessment.decisionAuthority) }} ·
              {{ getAvailabilityLabel(step.supervision.v21Assessment.availability) }}
            </small>
          </article>
        </div>
      </section>

      <section class="execution-inspector__section">
        <h5>Approval Basis</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>审批状态</dt>
            <dd>{{ layerValue(step, "approval") }}</dd>
          </div>
          <div>
            <dt>审批 ID</dt>
            <dd>{{ step.supervision.approval.approvalId ?? "未记录" }}</dd>
          </div>
          <div>
            <dt>依据完整性</dt>
            <dd>
              {{ approvalBasis ? getAvailabilityLabel(approvalBasis.completeness) : "不可用" }}
            </dd>
          </div>
          <div>
            <dt>正式审计 / GuardEvent</dt>
            <dd>
              {{ approvalBasis?.officialDecision.policyAuditId ?? "未记录" }} /
              {{ approvalBasis?.sourceContext.eventId ?? "未记录" }}
            </dd>
          </div>
          <div class="is-wide">
            <dt>结构化依据</dt>
            <dd>{{ approvalBasisSummary(approvalBasis) }}</dd>
          </div>
          <div class="is-wide">
            <dt>请求上下文</dt>
            <dd>{{ approvalBasis?.sourceContext.taskPreview ?? "不可用" }}</dd>
          </div>
          <div>
            <dt>来源类型</dt>
            <dd>{{ listOrUnavailable(approvalBasis?.sourceContext.rawSourceTypes ?? []) }}</dd>
          </div>
          <div>
            <dt>来源信任</dt>
            <dd>{{ listOrUnavailable(approvalBasis?.sourceContext.sourceTrust ?? []) }}</dd>
          </div>
          <div class="is-wide">
            <dt>缺失原因</dt>
            <dd>{{ approvalMissingReasons(approvalBasis) }}</dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>Approval Resolution</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>终态</dt>
            <dd>{{ approvalBasis?.resolution.status ?? "不可用" }}</dd>
          </div>
          <div>
            <dt>决议</dt>
            <dd>{{ approvalResolutionDecision(approvalBasis) }}</dd>
          </div>
          <div>
            <dt>来源 / 操作者</dt>
            <dd>{{ approvalResolutionActor(approvalBasis) }}</dd>
          </div>
          <div>
            <dt>决议时间</dt>
            <dd>{{ formatOptionalTime(approvalBasis?.resolution.resolvedAt ?? null) }}</dd>
          </div>
          <div class="is-wide">
            <dt>决议原因</dt>
            <dd>{{ approvalBasis?.resolution.resolutionReason ?? "未记录" }}</dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>Enforcement</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>门控状态</dt>
            <dd>{{ layerValue(step, "enforcement") }}</dd>
          </div>
          <div>
            <dt>Binding</dt>
            <dd>{{ step.supervision.enforcement.bindingCheckStatus }}</dd>
          </div>
          <div class="is-wide">
            <dt>证据边界</dt>
            <dd>
              {{
                step.supervision.enforcement.availability === "unavailable"
                  ? "强绑定门控证据尚未随 Trace 返回；不能由 DENY 推断 BLOCKED。"
                  : step.supervision.enforcement.reasonCodes.join(" · ") || "已记录"
              }}
            </dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>Runtime Outcome</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>执行结果</dt>
            <dd>{{ layerValue(step, "execution") }}</dd>
          </div>
          <div>
            <dt>运行时收据</dt>
            <dd>{{ step.supervision.execution.receiptRecorded ? "已唯一关联" : "未确认" }}</dd>
          </div>
          <div>
            <dt>调用时间</dt>
            <dd>{{ formatOptionalTime(step.supervision.execution.invokedAt) }}</dd>
          </div>
          <div>
            <dt>完成时间</dt>
            <dd>{{ formatOptionalTime(step.supervision.execution.completedAt) }}</dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>来源、权威与完整性</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>Source</dt>
            <dd>{{ getSourceModeLabel(step.supervision.semantics.elementSourceMode) }}</dd>
          </div>
          <div>
            <dt>Authority</dt>
            <dd>{{ getAuthorityLabel(step.supervision.semantics.decisionAuthority) }}</dd>
          </div>
          <div>
            <dt>Certainty</dt>
            <dd>{{ getCertaintyLabel(step.supervision.semantics.certainty) }}</dd>
          </div>
          <div>
            <dt>Availability</dt>
            <dd>{{ getAvailabilityLabel(step.supervision.semantics.availability) }}</dd>
          </div>
          <div class="is-wide">
            <dt>Control Integrity</dt>
            <dd>{{ getControlIntegrityLabel(step.supervision.controlIntegrity.status) }}</dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>内容进入上下文</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>原始渠道</dt>
            <dd>{{ listOrUnavailable(step.supervision.contentIngressSummary.rawSourceTypes) }}</dd>
          </div>
          <div>
            <dt>信任标签</dt>
            <dd>{{ listOrUnavailable(step.supervision.contentIngressSummary.trustLabels) }}</dd>
          </div>
          <div>
            <dt>Taints</dt>
            <dd>{{ listOrUnavailable(step.supervision.contentIngressSummary.taints) }}</dd>
          </div>
          <div>
            <dt>稳定 SourceRef</dt>
            <dd>
              {{ listOrUnavailable(step.supervision.contentIngressSummary.stableSourceRefs) }}
            </dd>
          </div>
          <div class="is-wide">
            <dt>CT 归一化</dt>
            <dd>
              {{
                step.supervision.contentIngressSummary.ctNormalizationAvailability === "unavailable"
                  ? contentIngressUnavailable(step)
                  : listOrUnavailable(
                      step.supervision.contentIngressSummary.normalizedCtSourceTypes,
                    )
              }}
            </dd>
          </div>
        </dl>
      </section>

      <section v-if="step.events.length" class="execution-inspector__section">
        <h5>审计记录</h5>
        <ol class="execution-inspector__events">
          <li v-for="event in step.events" :key="event.auditId">
            <time :datetime="event.occurredAt">{{ formatTime(event.occurredAt) }}</time>
            <span>{{ event.label }}</span>
            <small>{{ recordTypeLabel(event.recordType) }}</small>
          </li>
        </ol>
      </section>

      <details v-if="step.policyChecks.length > 1" class="execution-inspector__checks">
        <summary>全部 {{ step.policyChecks.length }} 次安全判断</summary>
        <ol>
          <li v-for="check in step.policyChecks" :key="check.auditId">
            <div>
              <StatusBadge
                :label="getDecisionLabel(check.decision)"
                :tone="getDecisionTone(check.decision)"
              />
              <time :datetime="check.occurredAt">{{ formatTime(check.occurredAt) }}</time>
            </div>
            <p>{{ check.reason ?? "未记录判定原因" }}</p>
          </li>
        </ol>
      </details>

      <footer class="execution-inspector__actions">
        <RouterLink
          v-if="step.approvalId"
          class="execution-inspector__approval"
          :to="approvalRoute(step)"
        >
          {{ isMockStep(step) ? "查看审批依据（只读）" : "查看审批依据" }}
        </RouterLink>
        <button type="button" @click="emit('show-provenance', step)">查看溯源关系</button>
        <button
          v-if="step.primaryAuditId"
          type="button"
          @click="emit('select-event', step.primaryAuditId)"
        >
          查看审计记录
        </button>
      </footer>
    </template>

    <div v-else class="execution-inspector__empty">
      <MousePointer2 :size="22" aria-hidden="true" />
      <strong>选择一个运行步骤</strong>
      <p>查看正式决策、审批、门控、运行时收据与关联证据。</p>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { MousePointer2 } from "@lucide/vue";

import {
  getAvailabilityLabel,
  getAuthorityLabel,
  getCertaintyLabel,
  getControlIntegrityLabel,
  getSemanticsSummary,
  getSourceModeLabel,
  getSupervisionLayerDisplays,
  type SupervisionLayerKey,
} from "../../data/evidence/runtime-supervision-display.ts";
import { getExecutionCategoryLabel } from "../../data/evidence/execution-trace";
import type {
  AuditRecordType,
  ExecutionStepViewModel,
  TraceLifecycleState,
} from "../../types/dashboard";
import type { ApprovalBasisViewModel } from "../../types/runtime-supervision";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
} from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";
import ExecutionSupervisionCapsules from "./ExecutionSupervisionCapsules.vue";

defineOptions({ name: "ExecutionStepInspector" });

const props = defineProps<{
  approvalBasis?: ApprovalBasisViewModel;
  lifecycleState: TraceLifecycleState;
  step?: ExecutionStepViewModel;
  stepNumber?: number;
}>();

const emit = defineEmits<{
  "select-event": [auditId: string];
  "show-provenance": [step: ExecutionStepViewModel];
}>();

function displayStatus(step: ExecutionStepViewModel): string {
  const isTerminal = ["completed", "failed", "cancelled"].includes(props.lifecycleState);
  if (!isTerminal || step.settled) return step.statusLabel;
  if (step.approval === "pending") return "运行已结束，审批结果未确认";
  if (step.receiptExpectation === "required") return "运行已结束，执行结果未确认";
  return step.statusLabel;
}

function recordTypeLabel(recordType: AuditRecordType): string {
  const labels: Record<AuditRecordType, string> = {
    config_audit: "配置审计",
    policy_evaluation: "安全判断",
    runtime_observation: "运行观察",
    runtime_outcome: "运行结果",
    unknown: "审计记录",
  };
  return labels[recordType];
}

function formatTime(value: string): string {
  return formatDashboardDateTime(value) || "未记录";
}

function formatOptionalTime(value: string | null): string {
  return value ? formatTime(value) : "未记录";
}

function listOrUnavailable(values: readonly string[]): string {
  return values.length ? values.join(" · ") : "不可用";
}

function approvalBasisSummary(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "结构化审批依据不可用，不从判定原因、关键词或 Shadow 结果推导。";
  if (basis.completeness === "recorded") {
    return "已从当前执行步骤唯一选定的正式 ASK 与审批证据生成。";
  }
  if (basis.completeness === "unavailable") {
    return "关键身份或原始审批证据不可用；该依据仅供只读调查。";
  }
  return "当前证据窗口或请求事实不完整；该依据仅供只读调查。";
}

function approvalMissingReasons(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "APPROVAL_BASIS_UNAVAILABLE";
  return basis.missingReasons.length ? basis.missingReasons.join(" · ") : "无";
}

function approvalResolutionDecision(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "不可用";
  if (basis.resolution.decision === "allow_once") return "单次放行";
  if (basis.resolution.decision === "deny") return "拒绝";
  return "尚未决议";
}

function approvalResolutionActor(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "不可用";
  const source = basis.resolution.resolutionSource ?? "未记录来源";
  const actor = basis.resolution.resolvedBy ?? "未记录操作者";
  return `${source} / ${actor}`;
}

function layerValue(step: ExecutionStepViewModel, key: SupervisionLayerKey): string {
  return getSupervisionLayerDisplays(step).find((layer) => layer.key === key)?.value ?? "不可用";
}

function v21Disposition(step: ExecutionStepViewModel): string {
  return step.supervision.v21Assessment.fastDisposition ?? "不可用";
}

function v21Summary(step: ExecutionStepViewModel): string {
  const assessment = step.supervision.v21Assessment;
  if (assessment.availability === "unavailable") {
    return "当前 Trace 未携带可展示的 V2.1 影子评估。";
  }
  if (assessment.authorityVerification === "conflicted") {
    return "影子证据不完整或与正式判定冲突，不提升其权威。";
  }
  return `记录终值 ${assessment.recordedFinalDecision ?? "未知"}；仅作影子解释，不改变正式决策。`;
}

function isMockStep(step: ExecutionStepViewModel): boolean {
  return step.supervision.semantics.elementSourceMode === "mock";
}

function contentIngressUnavailable(step: ExecutionStepViewModel): string {
  return isMockStep(step)
    ? "CT 归一化不可用；溯源视图仅展示明确标记的 Mock 内容入口链。"
    : "CT 归一化不可用；Live 数据不会回退到 Fixture。";
}

function approvalRoute(step: ExecutionStepViewModel) {
  return {
    path: `/approvals/${step.approvalId}`,
    query: isMockStep(step) ? { readonly: "1" } : {},
  };
}
</script>

<style scoped lang="scss">
.execution-inspector {
  align-content: start;
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-4);
  grid-auto-rows: max-content;
  max-height: 44rem;
  min-width: 0;
  overflow-y: auto;
  overscroll-behavior-y: contain;
  padding: var(--space-4);
  scrollbar-width: thin;
}

.execution-inspector__header {
  align-items: start;
  border-bottom: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-3);
  justify-content: space-between;
  padding-bottom: var(--space-3);
}

.execution-inspector__header > div,
.execution-inspector__state {
  display: grid;
  gap: 0.2rem;
  min-width: 0;
}

.execution-inspector__header span,
.execution-inspector__header code,
.execution-inspector__state span,
.execution-inspector dt,
.execution-inspector__events :is(time, small),
.execution-inspector__checks time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-inspector__header h4,
.execution-inspector__header code,
.execution-inspector__state strong {
  margin: 0;
  overflow-wrap: anywhere;
}

.execution-inspector__header h4 {
  font-size: var(--font-size-16);
}

.execution-inspector__facts,
.execution-inspector__detail-grid {
  display: grid;
  gap: var(--space-2);
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
}

.execution-inspector__facts > div,
.execution-inspector__detail-grid > div {
  background: var(--color-surface-muted);
  border-radius: var(--radius-1);
  display: grid;
  gap: 0.2rem;
  min-width: 0;
  padding: var(--space-2);
}

.execution-inspector__detail-grid > .is-wide {
  grid-column: 1 / -1;
}

.execution-inspector dd {
  font-size: var(--font-size-12);
  margin: 0;
  overflow-wrap: anywhere;
}

.execution-inspector__section {
  display: grid;
  gap: var(--space-2);
}

.execution-inspector__section h5,
.execution-inspector__section p {
  margin: 0;
}

.execution-inspector__section h5 {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  letter-spacing: 0.02em;
}

.execution-inspector__comparison {
  display: grid;
  gap: var(--space-2);
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.execution-inspector__comparison article {
  border: 1px solid var(--color-border);
  border-left: 3px solid var(--color-active);
  border-radius: var(--radius-1);
  display: grid;
  gap: 0.3rem;
  min-width: 0;
  padding: var(--space-2);
}

.execution-inspector__comparison article.is-shadow {
  border-left-color: var(--color-warning);
}

.execution-inspector__comparison span,
.execution-inspector__comparison small {
  color: var(--color-text-subtle);
  font-family: var(--font-family-mono);
  font-size: 0.58rem;
}

.execution-inspector__comparison strong {
  font-size: var(--font-size-12);
}

.execution-inspector__comparison p {
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  line-height: 1.45;
}

.execution-inspector__events,
.execution-inspector__checks ol {
  display: grid;
  gap: var(--space-2);
  list-style: none;
  margin: 0;
  padding: 0;
}

.execution-inspector__events li,
.execution-inspector__checks li {
  border-left: 2px solid var(--color-border-strong);
  display: grid;
  gap: 0.15rem;
  padding-left: var(--space-2);
}

.execution-inspector__checks summary {
  color: var(--color-text-muted);
  cursor: pointer;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
}

.execution-inspector__checks ol {
  margin-top: var(--space-2);
}

.execution-inspector__checks li > div {
  align-items: center;
  display: flex;
  gap: var(--space-2);
}

.execution-inspector__checks p {
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  margin: 0;
}

.execution-inspector__actions {
  border-top: 1px solid var(--color-border);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  padding-top: var(--space-3);
}

.execution-inspector__actions :is(button, a) {
  align-items: center;
  background: transparent;
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-1);
  color: var(--color-text-muted);
  display: inline-flex;
  font-size: var(--font-size-11);
  justify-content: center;
  min-height: 2.375rem;
  padding: 0 var(--space-3);
  text-decoration: none;
}

.execution-inspector__actions .execution-inspector__approval {
  border-color: var(--color-warning-border);
  color: var(--color-warning-strong);
}

.execution-inspector__empty {
  align-content: center;
  color: var(--color-text-subtle);
  display: grid;
  gap: var(--space-2);
  justify-items: center;
  min-height: 18rem;
  text-align: center;
}

.execution-inspector__empty p {
  margin: 0;
  max-width: 16rem;
}

@media (max-width: 82rem) {
  .execution-inspector {
    max-height: none;
  }
}

@media (max-width: 30rem) {
  .execution-inspector__comparison,
  .execution-inspector__facts,
  .execution-inspector__detail-grid {
    grid-template-columns: 1fr;
  }

  .execution-inspector__detail-grid > .is-wide {
    grid-column: auto;
  }
}
</style>
