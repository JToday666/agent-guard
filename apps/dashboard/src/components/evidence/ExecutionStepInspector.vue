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
          :label="getDecisionLabel(step.decision)"
          :tone="getDecisionTone(step.decision)"
        />
      </header>

      <div class="execution-inspector__state">
        <strong>{{ displayStatus(step) }}</strong>
        <span>{{ getExecutionApprovalLabel(step.approval) }}</span>
      </div>

      <dl class="execution-inspector__facts">
        <div>
          <dt>资源目标</dt>
          <dd>{{ step.resourceSummary ?? "未记录" }}</dd>
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

      <section v-if="step.decisionReason" class="execution-inspector__section">
        <h5>判定原因</h5>
        <p>{{ step.decisionReason }}</p>
      </section>

      <section v-if="step.events.length" class="execution-inspector__section">
        <h5>步骤记录</h5>
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
          v-if="step.approval === 'pending' && step.approvalId"
          class="execution-inspector__approval"
          :to="`/approvals/${step.approvalId}`"
        >
          处理审批
        </RouterLink>
        <button type="button" @click="emit('show-provenance', step)">查看安全依据</button>
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
      <p>查看安全判断、审批状态、运行结果和关联审计记录。</p>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { MousePointer2 } from "@lucide/vue";

import {
  getExecutionApprovalLabel,
  getExecutionCategoryLabel,
} from "../../data/evidence/execution-trace";
import type {
  AuditRecordType,
  ExecutionStepViewModel,
  TraceLifecycleState,
} from "../../types/dashboard";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
} from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({ name: "ExecutionStepInspector" });

const props = defineProps<{
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
  max-height: 38rem;
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

.execution-inspector__header > div {
  display: grid;
  gap: var(--space-1);
  min-width: 0;
}

.execution-inspector__header span,
.execution-inspector__header code,
.execution-inspector__state span,
.execution-inspector__facts dt,
.execution-inspector__events :is(time, small),
.execution-inspector__checks time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-inspector__header h4 {
  font-size: var(--font-size-16);
  margin: 0;
  overflow-wrap: anywhere;
}

.execution-inspector__header code {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.execution-inspector__state {
  background: var(--color-surface-muted);
  border-left: 3px solid var(--color-active);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-2) var(--space-3);
}

.execution-inspector__facts {
  display: grid;
  gap: 1px;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
}

.execution-inspector__facts > div {
  background: var(--color-surface-muted);
  display: grid;
  gap: var(--space-1);
  min-width: 0;
  padding: var(--space-3);
}

.execution-inspector__facts dd {
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
  font-size: var(--font-size-12);
}

.execution-inspector__section p {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  overflow-wrap: anywhere;
}

.execution-inspector__events,
.execution-inspector__checks ol {
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}

.execution-inspector__events li,
.execution-inspector__checks li {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-2) 0;
}

.execution-inspector__events span {
  font-size: var(--font-size-12);
}

.execution-inspector__checks summary {
  color: var(--color-link);
  cursor: pointer;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
}

.execution-inspector__checks ol {
  padding-top: var(--space-2);
}

.execution-inspector__checks li > div {
  align-items: center;
  display: flex;
  gap: var(--space-2);
  justify-content: space-between;
}

.execution-inspector__checks p {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
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
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-link);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  justify-content: center;
  min-height: 2.375rem;
  padding: 0 var(--space-3);
  text-decoration: none;
}

.execution-inspector__actions .execution-inspector__approval {
  background: var(--color-warning-soft);
  border-color: var(--color-warning-border);
  color: var(--color-warning-strong);
}

.execution-inspector__empty {
  align-items: center;
  color: var(--color-text-subtle);
  display: grid;
  gap: var(--space-2);
  justify-items: center;
  min-height: 18rem;
  text-align: center;
}

.execution-inspector__empty p {
  font-size: var(--font-size-12);
  margin: 0;
  max-width: 16rem;
}

@media (max-width: 82rem) {
  .execution-inspector {
    max-height: none;
    overflow-y: visible;
  }
}
</style>
