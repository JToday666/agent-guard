<template>
  <section class="execution-trace" aria-labelledby="execution-trace-title">
    <header class="execution-trace__header">
      <div>
        <span class="execution-trace__eyebrow">智能体运行状态</span>
        <div class="execution-trace__state-line">
          <span
            class="execution-trace__state-dot"
            :class="`execution-trace__state-dot--${trace.lifecycleState}`"
            aria-hidden="true"
          ></span>
          <h3 id="execution-trace-title">{{ trace.lifecycleLabel }}</h3>
        </div>
        <p>按动作查看安全判断、人工审批与运行结果。</p>
      </div>
      <div class="execution-trace__connection" :class="`is-${pollingState.status}`">
        <component :is="connectionIcon" :size="16" aria-hidden="true" />
        <span>{{ connectionLabel }}</span>
      </div>
    </header>

    <ol v-if="trace.actions.length" class="execution-trace__list">
      <li
        v-for="(action, index) in trace.actions"
        :key="action.actionId"
        class="execution-trace__step"
        :class="{ 'execution-trace__step--selected': action.actionId === selectedActionId }"
        :data-action-id="action.actionId"
      >
        <div class="execution-trace__rail" aria-hidden="true">
          <span>{{ String(index + 1).padStart(2, "0") }}</span>
        </div>
        <article
          class="execution-action"
          :class="`execution-action--${action.decision}`"
          :aria-labelledby="`execution-action-${index}`"
        >
          <header class="execution-action__header">
            <div class="execution-action__identity">
              <button
                :id="`execution-action-${index}`"
                type="button"
                class="execution-action__title"
                @click="emit('select-action', action.actionId)"
              >
                {{ action.displayName }}
              </button>
              <code>{{ action.actionName ?? action.actionId }}</code>
            </div>
            <StatusBadge
              :label="getDecisionLabel(action.decision)"
              :tone="getDecisionTone(action.decision)"
            />
          </header>

          <div class="execution-action__status">
            <component
              :is="runtimeIcon(action)"
              :class="{ 'is-running': action.phase === 'waiting_receipt' }"
              :size="19"
              aria-hidden="true"
            />
            <div>
              <strong>{{ action.statusLabel }}</strong>
              <span>{{ getExecutionApprovalLabel(action.approval) }}</span>
            </div>
          </div>

          <dl class="execution-action__facts">
            <div>
              <dt>目标</dt>
              <dd>{{ action.resourceSummary ?? "未记录" }}</dd>
            </div>
            <div>
              <dt>风险</dt>
              <dd>
                {{ action.riskScore ?? "未记录" }} ·
                {{ getRiskSeverityLabel(action.severity) }}
              </dd>
            </div>
            <div>
              <dt>安全判断</dt>
              <dd>{{ action.policyChecks.length }} 次</dd>
            </div>
            <div>
              <dt>更新时间</dt>
              <dd>
                <time :datetime="action.lastUpdatedAt">{{ formatTime(action.lastUpdatedAt) }}</time>
              </dd>
            </div>
          </dl>

          <p v-if="action.decisionReason" class="execution-action__reason">
            {{ action.decisionReason }}
          </p>

          <footer class="execution-action__actions">
            <RouterLink
              v-if="action.approval === 'pending' && action.approvalId"
              class="execution-action__approval"
              :to="`/approvals/${action.approvalId}`"
            >
              处理审批
            </RouterLink>
            <button type="button" @click="emit('show-provenance', action.actionId)">
              查看安全依据
            </button>
            <button
              v-if="action.primaryAuditId"
              type="button"
              @click="emit('select-event', action.primaryAuditId)"
            >
              查看审计记录
            </button>
          </footer>
        </article>
      </li>
    </ol>

    <div v-else class="execution-trace__empty">
      <CircleDashed :size="22" aria-hidden="true" />
      <div>
        <strong>暂未发现可展示的执行动作</strong>
        <p>完整记录仍可在审计记录中查看。</p>
      </div>
      <button type="button" @click="emit('show-audit')">查看审计记录</button>
    </div>
  </section>
</template>

<script setup lang="ts">
import {
  Ban,
  CheckCircle2,
  CircleDashed,
  CircleX,
  LoaderCircle,
  PauseCircle,
  RefreshCw,
  Wifi,
  WifiOff,
} from "@lucide/vue";
import { computed } from "vue";

import type {
  ExecutionActionViewModel,
  ExecutionTraceViewModel,
  TracePollingState,
} from "../../types/dashboard";
import { getExecutionApprovalLabel } from "../../data/evidence/execution-trace";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
} from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({ name: "ExecutionTrace" });

const props = defineProps<{
  trace: ExecutionTraceViewModel;
  pollingState: TracePollingState;
  selectedActionId?: string;
}>();

const emit = defineEmits<{
  "select-action": [actionId: string];
  "select-event": [eventId: string];
  "show-audit": [];
  "show-provenance": [actionId: string];
}>();

const connectionIcon = computed(() => {
  if (props.pollingState.status === "checking") return RefreshCw;
  if (props.pollingState.status === "backoff") return WifiOff;
  if (props.pollingState.status === "paused") return PauseCircle;
  if (props.pollingState.status === "stopped") return CheckCircle2;
  if (props.pollingState.status === "live") return Wifi;
  return CircleDashed;
});

const connectionLabel = computed(() => {
  if (props.pollingState.status === "checking") return "正在更新";
  if (props.pollingState.status === "backoff") {
    const seconds = Math.max(1, Math.round((props.pollingState.retryInMs ?? 0) / 1000));
    return `${seconds} 秒后重试`;
  }
  if (props.pollingState.status === "paused") return "页面隐藏，已暂停更新";
  if (props.pollingState.status === "stopped") {
    const allActionsConfirmed =
      props.trace.actions.length > 0 &&
      props.trace.actions.every((action) => action.phase === "terminal");
    return allActionsConfirmed ? "运行结果已确认" : "运行已结束，部分结果未确认";
  }
  if (props.pollingState.status === "live") return "自动更新中";
  return "等待首次更新";
});

function runtimeIcon(action: ExecutionActionViewModel) {
  if (action.phase === "waiting_receipt") return LoaderCircle;
  if (action.execution === "executed") return CheckCircle2;
  if (action.execution === "failed") return CircleX;
  if (action.execution === "not_invoked") return Ban;
  return CircleDashed;
}

function formatTime(value: string): string {
  return formatDashboardDateTime(value) || "未记录";
}
</script>

<style scoped lang="scss">
.execution-trace {
  display: grid;
  gap: var(--space-5);
}

.execution-trace__header {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-5);
  justify-content: space-between;
  padding: var(--space-4) var(--space-5);
}

.execution-trace__header > div:first-child {
  display: grid;
  gap: var(--space-1);
}

.execution-trace__eyebrow {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  letter-spacing: 0.08em;
}

.execution-trace__state-line {
  align-items: center;
  display: flex;
  gap: var(--space-2);
}

.execution-trace__state-line h3,
.execution-trace__header p,
.execution-trace__empty p {
  margin: 0;
}

.execution-trace__state-line h3 {
  font-size: var(--font-size-18);
}

.execution-trace__header p,
.execution-trace__empty p {
  color: var(--color-text-muted);
  font-size: var(--font-size-13);
}

.execution-trace__state-dot {
  background: var(--color-active);
  border-radius: 50%;
  box-shadow: var(--glow-live);
  height: 0.65rem;
  width: 0.65rem;
}

.execution-trace__state-dot--waiting_approval {
  background: var(--color-warning);
  box-shadow: var(--glow-warning);
}

.execution-trace__state-dot--failed,
.execution-trace__state-dot--cancelled {
  background: var(--color-danger);
  box-shadow: none;
}

.execution-trace__state-dot--completed {
  background: var(--color-success);
  box-shadow: none;
}

.execution-trace__connection {
  align-items: center;
  color: var(--color-text-subtle);
  display: inline-flex;
  flex: 0 0 auto;
  font-size: var(--font-size-12);
  gap: var(--space-2);
}

.execution-trace__connection.is-backoff {
  color: var(--color-danger);
}

.execution-trace__connection.is-checking svg {
  animation: execution-spin 1.5s linear infinite;
  color: var(--color-active);
}

.execution-trace__list {
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}

.execution-trace__step {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: 2.4rem minmax(0, 1fr);
  position: relative;
}

.execution-trace__step:not(:last-child) {
  padding-bottom: var(--space-5);
}

.execution-trace__step:not(:last-child)::before {
  background: var(--color-border-strong);
  bottom: 0;
  content: "";
  left: 1.15rem;
  position: absolute;
  top: 2rem;
  width: 1px;
}

.execution-trace__rail {
  position: relative;
  z-index: 1;
}

.execution-trace__rail span {
  align-items: center;
  background: var(--color-shell);
  border: 3px solid var(--color-page);
  border-radius: 50%;
  color: var(--color-shell-text);
  display: flex;
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  height: 2.35rem;
  justify-content: center;
  width: 2.35rem;
}

.execution-action {
  --action-accent: var(--color-border-strong);
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-left: 4px solid var(--action-accent);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-4);
  min-width: 0;
  padding: var(--space-4) var(--space-5);
  transition:
    border-color var(--transition-fast),
    box-shadow var(--transition-fast);
}

.execution-action--allow {
  --action-accent: var(--color-success);
}

.execution-action--ask {
  --action-accent: var(--color-warning);
}

.execution-action--deny {
  --action-accent: var(--color-danger);
}

.execution-trace__step--selected .execution-action {
  border-color: var(--color-active-border);
  box-shadow: var(--glow-active);
}

.execution-action__header,
.execution-action__actions,
.execution-action__status {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
}

.execution-action__header {
  gap: var(--space-3);
  justify-content: space-between;
}

.execution-action__identity {
  display: grid;
  gap: var(--space-1);
  min-width: 0;
}

.execution-action__title {
  background: transparent;
  border: 0;
  color: var(--color-text);
  cursor: pointer;
  font: inherit;
  font-size: var(--font-size-16);
  font-weight: var(--font-weight-bold);
  justify-self: start;
  min-height: 2.25rem;
  padding: 0;
  text-align: left;
}

.execution-action__title:hover {
  color: var(--color-link);
}

.execution-action__title:focus-visible,
.execution-action__actions :is(button, a):focus-visible,
.execution-trace__empty button:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: 2px;
}

.execution-action__identity code {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  overflow-wrap: anywhere;
}

.execution-action__status {
  background: var(--color-surface-muted);
  gap: var(--space-3);
  padding: var(--space-3);
}

.execution-action__status > svg {
  color: var(--color-active);
  flex: 0 0 auto;
}

.execution-action__status > svg.is-running {
  animation: execution-spin 1.1s linear infinite;
}

.execution-action__status > div {
  display: grid;
  gap: 0.1rem;
}

.execution-action__status span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-action__facts {
  display: grid;
  gap: var(--space-3);
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
}

.execution-action__facts > div {
  border-left: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  min-width: 0;
  padding-left: var(--space-3);
}

.execution-action__facts dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
}

.execution-action__facts dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.execution-action__reason {
  color: var(--color-text-muted);
  margin: 0;
}

.execution-action__actions {
  border-top: 1px solid var(--color-border);
  gap: var(--space-2);
  padding-top: var(--space-3);
}

.execution-action__actions :is(button, a),
.execution-trace__empty button {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  display: inline-flex;
  font: inherit;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  justify-content: center;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
  text-decoration: none;
}

.execution-action__actions :is(button, a):hover,
.execution-trace__empty button:hover {
  border-color: var(--color-active);
}

.execution-action__actions .execution-action__approval {
  background: var(--color-warning-soft);
  border-color: var(--color-warning-border);
  color: var(--color-warning-strong);
}

.execution-trace__empty {
  align-items: center;
  border: 1px dashed var(--color-border-strong);
  color: var(--color-text-subtle);
  display: grid;
  gap: var(--space-4);
  grid-template-columns: auto minmax(0, 1fr) auto;
  padding: var(--space-5);
}

@keyframes execution-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 62rem) {
  .execution-action__facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 44rem) {
  .execution-trace__header,
  .execution-trace__empty {
    align-items: start;
    grid-template-columns: 1fr;
  }

  .execution-trace__header {
    flex-direction: column;
  }

  .execution-action__facts {
    grid-template-columns: 1fr;
  }
}

@media (prefers-reduced-motion: reduce) {
  .execution-action__status > svg.is-running,
  .execution-trace__connection.is-checking svg {
    animation: none;
  }
}
</style>
