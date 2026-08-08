<template>
  <section class="execution-trace" aria-labelledby="execution-trace-title">
    <header class="execution-trace__header">
      <div class="execution-trace__heading">
        <span class="execution-trace__eyebrow">智能体运行状态</span>
        <div class="execution-trace__state-line">
          <span
            class="execution-trace__state-dot"
            :class="`execution-trace__state-dot--${trace.lifecycleState}`"
            aria-hidden="true"
          ></span>
          <h3 id="execution-trace-title">{{ trace.lifecycleLabel }}</h3>
        </div>
        <p>按运行步骤查看安全判断、人工审批与执行结果。</p>
      </div>

      <div class="execution-trace__connection" :class="`is-${pollingState.status}`">
        <component :is="connectionIcon" :size="16" aria-hidden="true" />
        <span>{{ connectionLabel }}</span>
      </div>
    </header>

    <dl v-if="trace.steps.length" class="execution-trace__summary" aria-label="运行轨迹摘要">
      <div>
        <dt>运行步骤</dt>
        <dd>{{ trace.steps.length }}</dd>
      </div>
      <div>
        <dt>受控动作</dt>
        <dd>{{ actionCount }}</dd>
      </div>
      <div>
        <dt>等待审批</dt>
        <dd>{{ pendingApprovalCount }}</dd>
      </div>
      <div>
        <dt>风险步骤</dt>
        <dd>{{ riskStepCount }}</dd>
      </div>
    </dl>

    <p v-if="isWindowPartial" class="execution-trace__window-note">
      当前只展示已加载审计窗口中的运行步骤，较早的动作起点可能未包含在本次响应中。
    </p>

    <div v-if="trace.steps.length" class="execution-trace__toolbar">
      <div class="execution-trace__search">
        <label class="sr-only" for="execution-step-search">搜索运行步骤</label>
        <Search :size="15" aria-hidden="true" />
        <input
          id="execution-step-search"
          v-model.trim="searchQuery"
          autocomplete="off"
          name="execution-step-search"
          spellcheck="false"
          type="search"
          placeholder="搜索步骤、工具或资源…"
        />
        <button
          v-if="searchQuery"
          type="button"
          aria-label="清除运行步骤搜索"
          title="清除搜索"
          @click="searchQuery = ''"
        >
          <X :size="14" aria-hidden="true" />
        </button>
      </div>

      <div class="execution-trace__filters" aria-label="运行步骤筛选">
        <button
          v-for="option in filterOptions"
          :key="option.id"
          type="button"
          :aria-pressed="activeFilter === option.id"
          @click="activeFilter = option.id"
        >
          {{ option.label }}
          <span>{{ option.count }}</span>
        </button>
      </div>

      <span class="execution-trace__result-count" role="status">
        显示 {{ visibleSteps.length }} / {{ trace.steps.length }} 个步骤
      </span>
    </div>

    <div v-if="pendingUpdateCount" class="execution-trace__updates">
      <span>运行轨迹有 {{ pendingUpdateCount }} 个新增或更新步骤</span>
      <button type="button" @click="showLatestUpdate">
        <ArrowDownToLine :size="15" aria-hidden="true" />
        查看最新
      </button>
    </div>
    <span class="sr-only" aria-live="polite">{{ priorityAnnouncement }}</span>

    <ol v-if="visibleSteps.length" class="execution-trace__list">
      <li
        v-for="(step, index) in visibleSteps"
        :key="step.stepId"
        class="execution-trace__step"
        :class="{
          'execution-trace__step--current': step.stepId === currentStepId,
          'execution-trace__step--selected': isSelected(step),
          'execution-trace__step--updated': pendingUpdateStepIds.has(step.stepId),
        }"
        :data-action-id="step.actionId ?? undefined"
        :data-step-id="step.stepId"
      >
        <div class="execution-trace__rail" aria-hidden="true">
          <span>{{ String(stepNumber(step)).padStart(2, "0") }}</span>
        </div>

        <article
          class="execution-action"
          :class="[`execution-action--${step.decision}`, `execution-action--${step.kind}`]"
          :aria-labelledby="`execution-step-title-${index}`"
        >
          <button
            :id="`execution-step-title-${index}`"
            type="button"
            class="execution-action__summary"
            :aria-controls="`execution-step-detail-${index}`"
            :aria-expanded="expandedStepIds.has(step.stepId)"
            @click="handleStepToggle(step)"
          >
            <span class="execution-action__identity">
              <span class="execution-action__category-icon" aria-hidden="true">
                <component :is="categoryIcon(step.category)" :size="17" />
              </span>
              <span class="execution-action__name">
                <strong>{{ step.displayName }}</strong>
                <code v-if="step.actionName" translate="no">{{ step.actionName }}</code>
                <small v-else>{{ getExecutionCategoryLabel(step.category) }}</small>
              </span>
            </span>

            <span class="execution-action__runtime">
              <component
                :is="runtimeIcon(step)"
                :class="{ 'is-running': step.phase === 'waiting_receipt' }"
                :size="17"
                aria-hidden="true"
              />
              <span>
                <strong>{{ displayStatus(step) }}</strong>
                <small>{{ getExecutionApprovalLabel(step.approval) }}</small>
              </span>
            </span>

            <StatusBadge
              :label="getDecisionLabel(step.decision)"
              :tone="getDecisionTone(step.decision)"
            />

            <span v-if="step.stepId === currentStepId" class="execution-action__current">
              当前
            </span>
            <ChevronDown
              class="execution-action__chevron"
              :class="{ 'is-open': expandedStepIds.has(step.stepId) }"
              :size="17"
              aria-hidden="true"
            />
          </button>

          <div
            v-if="expandedStepIds.has(step.stepId)"
            :id="`execution-step-detail-${index}`"
            class="execution-action__detail"
          >
            <dl class="execution-action__facts">
              <div>
                <dt>资源目标</dt>
                <dd>{{ step.resourceSummary ?? "未记录" }}</dd>
              </div>
              <div>
                <dt>风险</dt>
                <dd>
                  {{ step.riskScore ?? "未记录" }} ·
                  {{ getRiskSeverityLabel(step.severity) }}
                </dd>
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

            <p v-if="step.decisionReason" class="execution-action__reason">
              <strong>判定原因</strong>
              <span>{{ step.decisionReason }}</span>
            </p>

            <section v-if="step.events.length" class="execution-action__events">
              <h4>步骤记录</h4>
              <ol>
                <li v-for="event in step.events" :key="event.auditId">
                  <time :datetime="event.occurredAt">{{ formatTime(event.occurredAt) }}</time>
                  <span>{{ event.label }}</span>
                  <small>{{ recordTypeLabel(event.recordType) }}</small>
                </li>
              </ol>
            </section>

            <details v-if="step.policyChecks.length > 1" class="execution-action__checks">
              <summary>查看全部 {{ step.policyChecks.length }} 次安全判断</summary>
              <ol>
                <li v-for="check in step.policyChecks" :key="check.auditId">
                  <StatusBadge
                    :label="getDecisionLabel(check.decision)"
                    :tone="getDecisionTone(check.decision)"
                  />
                  <time :datetime="check.occurredAt">{{ formatTime(check.occurredAt) }}</time>
                  <span>{{ check.reason ?? "未记录判定原因" }}</span>
                </li>
              </ol>
            </details>

            <footer class="execution-action__actions">
              <RouterLink
                v-if="step.approval === 'pending' && step.approvalId"
                class="execution-action__approval"
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
          </div>
        </article>
      </li>
    </ol>

    <div v-else-if="trace.steps.length" class="execution-trace__empty">
      <ListFilter :size="22" aria-hidden="true" />
      <div>
        <strong>当前条件没有匹配步骤</strong>
        <p>清除搜索或恢复全部筛选后继续查看。</p>
      </div>
      <button type="button" @click="resetFilters">恢复全部步骤</button>
    </div>

    <div v-else class="execution-trace__empty">
      <CircleDashed :size="22" aria-hidden="true" />
      <div>
        <strong>暂未记录运行步骤</strong>
        <p>已持久化的原始记录仍可在审计记录中查看。</p>
      </div>
      <button type="button" @click="emit('show-audit')">查看审计记录</button>
    </div>
  </section>
</template>

<script setup lang="ts">
import {
  Activity,
  ArrowDownToLine,
  Ban,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  CircleDashed,
  CircleX,
  Clock3,
  Database,
  FileCheck2,
  Layers3,
  ListFilter,
  LoaderCircle,
  MessageSquare,
  PauseCircle,
  Search,
  ShieldCheck,
  Wifi,
  WifiOff,
  Wrench,
  X,
} from "@lucide/vue";
import { computed, nextTick, ref, watch, type Component } from "vue";

import {
  getExecutionApprovalLabel,
  getExecutionCategoryLabel,
} from "../../data/evidence/execution-trace";
import type {
  AuditRecordType,
  ExecutionStepCategory,
  ExecutionStepViewModel,
  ExecutionTraceViewModel,
  TracePollingState,
} from "../../types/dashboard";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
} from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({ name: "ExecutionTrace" });

type StepFilter = "all" | "unconfirmed" | "approval" | "risk" | "failed";

const props = defineProps<{
  traceId: string;
  trace: ExecutionTraceViewModel;
  pollingState: TracePollingState;
  isWindowPartial?: boolean;
  selectedActionId?: string;
  selectedAuditId?: string;
}>();

const emit = defineEmits<{
  "select-event": [auditId: string];
  "select-step": [step: ExecutionStepViewModel];
  "show-audit": [];
  "show-provenance": [step: ExecutionStepViewModel];
}>();

const activeFilter = ref<StepFilter>("all");
const expandedStepIds = ref<ReadonlySet<string>>(new Set());
const pendingUpdateStepIds = ref<ReadonlySet<string>>(new Set());
const priorityAnnouncement = ref("");
const searchQuery = ref("");
let observedTraceId = "";
let revisionByStepId = new Map<string, string>();

const isTerminal = computed(() =>
  ["completed", "failed", "cancelled"].includes(props.trace.lifecycleState),
);
const actionCount = computed(
  () => props.trace.steps.filter((step) => step.kind === "action").length,
);
const pendingApprovalCount = computed(
  () => props.trace.steps.filter((step) => step.approval === "pending").length,
);
const riskStepCount = computed(() => props.trace.steps.filter((step) => isRiskStep(step)).length);
const pendingUpdateCount = computed(() => pendingUpdateStepIds.value.size);
const currentStepId = computed(() => {
  if (isTerminal.value) return "";
  const priority = [...props.trace.steps]
    .reverse()
    .find((step) =>
      ["waiting_approval", "approval_released", "waiting_receipt"].includes(step.phase),
    );
  return (
    priority?.stepId ?? [...props.trace.steps].reverse().find((step) => !step.settled)?.stepId ?? ""
  );
});

const filterOptions = computed(() => [
  { count: props.trace.steps.length, id: "all" as const, label: "全部" },
  {
    count: props.trace.steps.filter((step) => !step.settled).length,
    id: "unconfirmed" as const,
    label: "未确认",
  },
  {
    count: pendingApprovalCount.value,
    id: "approval" as const,
    label: "待审批",
  },
  { count: riskStepCount.value, id: "risk" as const, label: "风险" },
  {
    count: props.trace.steps.filter((step) => step.execution === "failed").length,
    id: "failed" as const,
    label: "失败",
  },
]);

const visibleSteps = computed(() => {
  const query = searchQuery.value.toLocaleLowerCase();
  return props.trace.steps.filter((step) => {
    const filterMatches =
      activeFilter.value === "all" ||
      (activeFilter.value === "unconfirmed" && !step.settled) ||
      (activeFilter.value === "approval" && step.approval === "pending") ||
      (activeFilter.value === "risk" && isRiskStep(step)) ||
      (activeFilter.value === "failed" && step.execution === "failed");
    if (!filterMatches) return false;
    if (!query) return true;
    return [
      step.displayName,
      step.actionName,
      step.resourceSummary,
      step.decisionReason,
      ...step.events.map((event) => event.label),
    ].some((value) => value?.toLocaleLowerCase().includes(query));
  });
});

const connectionIcon = computed(() => {
  if (props.pollingState.status === "backoff") return WifiOff;
  if (props.pollingState.status === "paused") return PauseCircle;
  if (props.pollingState.status === "stopped") return CheckCircle2;
  if (props.pollingState.status === "live" || props.pollingState.status === "checking") {
    return Wifi;
  }
  return CircleDashed;
});

const connectionLabel = computed(() => {
  if (props.pollingState.status === "checking") return "正在校准";
  if (props.pollingState.status === "backoff") {
    const seconds = Math.max(1, Math.round((props.pollingState.retryInMs ?? 0) / 1000));
    return `${seconds} 秒后重试`;
  }
  if (props.pollingState.status === "paused") return "页面隐藏，已暂停更新";
  if (props.pollingState.status === "stopped") {
    const requiredSteps = props.trace.steps.filter(
      (step) => step.receiptExpectation === "required",
    );
    const allResultsConfirmed =
      requiredSteps.length > 0 && requiredSteps.every((step) => step.phase === "terminal");
    return allResultsConfirmed ? "运行结果已确认" : "运行已结束，部分结果未确认";
  }
  if (props.pollingState.status === "live") return "自动更新中";
  return "等待首次更新";
});

watch(
  () => [props.traceId, ...props.trace.steps.map(stepRevision)],
  () => {
    if (observedTraceId !== props.traceId) {
      observedTraceId = props.traceId;
      revisionByStepId = new Map(
        props.trace.steps.map((step) => [step.stepId, stepRevision(step)]),
      );
      pendingUpdateStepIds.value = new Set();
      priorityAnnouncement.value = "";
      expandedStepIds.value = new Set(
        props.trace.steps.filter(shouldExpandByDefault).map((step) => step.stepId),
      );
      return;
    }

    const changed = props.trace.steps.filter(
      (step) => revisionByStepId.get(step.stepId) !== stepRevision(step),
    );
    revisionByStepId = new Map(props.trace.steps.map((step) => [step.stepId, stepRevision(step)]));
    if (!changed.length) return;

    pendingUpdateStepIds.value = new Set([
      ...pendingUpdateStepIds.value,
      ...changed.map((step) => step.stepId),
    ]);
    const expanded = new Set(expandedStepIds.value);
    changed.filter(shouldExpandByDefault).forEach((step) => expanded.add(step.stepId));
    expandedStepIds.value = expanded;
    const priorityChanges = changed.filter(
      (step) =>
        step.approval === "pending" || step.decision === "deny" || step.execution === "failed",
    );
    priorityAnnouncement.value = priorityChanges.length
      ? `有 ${priorityChanges.length} 个需要关注的运行步骤发生变化。`
      : "";
  },
  { immediate: true },
);

watch(
  () => [props.selectedActionId, props.selectedAuditId],
  () => {
    const selected = props.trace.steps.find(isSelected);
    if (!selected) return;
    expandedStepIds.value = new Set([...expandedStepIds.value, selected.stepId]);
  },
  { immediate: true },
);

function stepRevision(step: ExecutionStepViewModel): string {
  return [
    step.stepId,
    step.lastUpdatedAt,
    step.phase,
    step.decision,
    step.approval,
    step.execution,
    step.auditIds.join("\u0000"),
  ].join("\u0001");
}

function isRiskStep(step: ExecutionStepViewModel): boolean {
  return (
    step.decision === "ask" ||
    step.decision === "deny" ||
    step.severity === "critical" ||
    step.severity === "high"
  );
}

function shouldExpandByDefault(step: ExecutionStepViewModel): boolean {
  return (
    step.approval === "pending" ||
    step.decision === "deny" ||
    step.execution === "failed" ||
    step.phase === "waiting_receipt"
  );
}

function isSelected(step: ExecutionStepViewModel): boolean {
  return Boolean(
    (props.selectedActionId && step.actionId === props.selectedActionId) ||
    (props.selectedAuditId && step.auditIds.includes(props.selectedAuditId)),
  );
}

function stepNumber(step: ExecutionStepViewModel): number {
  return Math.max(1, props.trace.steps.findIndex((item) => item.stepId === step.stepId) + 1);
}

function handleStepToggle(step: ExecutionStepViewModel): void {
  const next = new Set(expandedStepIds.value);
  if (next.has(step.stepId)) next.delete(step.stepId);
  else next.add(step.stepId);
  expandedStepIds.value = next;
  markStepSeen(step.stepId);
  emit("select-step", step);
}

function markStepSeen(stepId: string): void {
  if (!pendingUpdateStepIds.value.has(stepId)) return;
  const next = new Set(pendingUpdateStepIds.value);
  next.delete(stepId);
  pendingUpdateStepIds.value = next;
  if (!next.size) priorityAnnouncement.value = "";
}

async function showLatestUpdate(): Promise<void> {
  const latest = [...props.trace.steps]
    .reverse()
    .find((step) => pendingUpdateStepIds.value.has(step.stepId));
  if (!latest) return;
  activeFilter.value = "all";
  searchQuery.value = "";
  expandedStepIds.value = new Set([...expandedStepIds.value, latest.stepId]);
  pendingUpdateStepIds.value = new Set();
  priorityAnnouncement.value = "";
  emit("select-step", latest);
  await nextTick();
  document
    .querySelector<HTMLElement>(`[data-step-id="${CSS.escape(latest.stepId)}"]`)
    ?.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "center" });
}

function resetFilters(): void {
  activeFilter.value = "all";
  searchQuery.value = "";
}

function displayStatus(step: ExecutionStepViewModel): string {
  if (!isTerminal.value || step.settled) return step.statusLabel;
  if (step.approval === "pending") return "运行已结束，审批结果未确认";
  if (step.receiptExpectation === "required") return "运行已结束，执行结果未确认";
  return step.statusLabel;
}

function runtimeIcon(step: ExecutionStepViewModel): Component {
  if (step.phase === "waiting_receipt") return LoaderCircle;
  if (step.phase === "waiting_approval") return Clock3;
  if (step.execution === "executed") return CheckCircle2;
  if (step.execution === "failed") return CircleX;
  if (step.execution === "not_invoked") return Ban;
  if (step.phase === "checked") return ShieldCheck;
  return CircleDashed;
}

function categoryIcon(category: ExecutionStepCategory): Component {
  const icons: Record<ExecutionStepCategory, Component> = {
    context: Layers3,
    memory: Database,
    message: MessageSquare,
    model_input: BrainCircuit,
    model_output: FileCheck2,
    tool: Wrench,
    tool_result: ShieldCheck,
    unknown: Activity,
  };
  return icons[category];
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

function prefersReducedMotion(): boolean {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}
</script>

<style scoped lang="scss">
.execution-trace {
  display: grid;
  gap: var(--space-4);
  min-width: 0;
}

.execution-trace__header {
  align-items: center;
  background: var(--color-surface-muted);
  border-block: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-5);
  justify-content: space-between;
  padding: var(--space-4) var(--space-5);
}

.execution-trace__heading {
  display: grid;
  gap: var(--space-1);
  min-width: 0;
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
.execution-trace__empty p,
.execution-action__reason {
  margin: 0;
}

.execution-trace__state-line h3 {
  font-size: var(--font-size-18);
  text-wrap: balance;
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
  flex: 0 0 auto;
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

.execution-trace__summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
}

.execution-trace__summary > div {
  border-left: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  min-width: 0;
  padding: var(--space-2) var(--space-4);
}

.execution-trace__summary > div:first-child {
  border-left: 0;
}

.execution-trace__summary dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-trace__summary dd {
  font-size: var(--font-size-18);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-bold);
  margin: 0;
}

.execution-trace__window-note {
  background: var(--color-warning-soft);
  border-left: 3px solid var(--color-warning-border);
  color: var(--color-warning-strong);
  font-size: var(--font-size-12);
  margin: 0;
  padding: var(--space-2) var(--space-3);
}

.execution-trace__toolbar {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}

.execution-trace__search {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  display: flex;
  flex: 1 1 17rem;
  min-height: 2.25rem;
  min-width: 0;
  padding-left: var(--space-3);
}

.execution-trace__search:focus-within {
  border-color: var(--color-focus);
  box-shadow: var(--shadow-focus);
}

.execution-trace__search > svg {
  color: var(--color-text-subtle);
  flex: 0 0 auto;
}

.execution-trace__search input {
  background: transparent;
  border: 0;
  color: var(--color-text);
  flex: 1;
  font: inherit;
  min-height: 2.25rem;
  min-width: 0;
  outline: 0;
  padding: 0 var(--space-2);
}

.execution-trace__search button {
  align-items: center;
  background: transparent;
  border: 0;
  color: var(--color-text-subtle);
  cursor: pointer;
  display: inline-flex;
  height: 2.25rem;
  justify-content: center;
  width: 2.25rem;
}

.execution-trace__filters {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-1);
}

.execution-trace__filters button,
.execution-trace__updates button,
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
  gap: var(--space-2);
  justify-content: center;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
  text-decoration: none;
  touch-action: manipulation;
  -webkit-tap-highlight-color: transparent;
}

.execution-trace__filters button[aria-pressed="true"] {
  background: var(--color-active-soft);
  border-color: var(--color-active-border);
  color: var(--color-active-strong);
}

.execution-trace__filters button span {
  color: var(--color-text-subtle);
  font-variant-numeric: tabular-nums;
}

.execution-trace__result-count {
  color: var(--color-text-subtle);
  flex: 0 0 auto;
  font-size: var(--font-size-11);
  margin-left: auto;
}

.execution-trace__updates {
  align-items: center;
  background: var(--color-active-soft);
  border-left: 3px solid var(--color-active);
  color: var(--color-active-strong);
  display: flex;
  font-size: var(--font-size-12);
  gap: var(--space-3);
  justify-content: space-between;
  padding: var(--space-2) var(--space-3);
}

.execution-trace__list {
  border-top: 1px solid var(--color-border);
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}

.execution-trace__step {
  --step-accent: var(--color-border-strong);
  content-visibility: auto;
  contain-intrinsic-size: auto 5rem;
  display: grid;
  grid-template-columns: 2.75rem minmax(0, 1fr);
  min-width: 0;
  position: relative;
}

.execution-trace__step:not(:last-child)::before {
  background: var(--color-border-strong);
  bottom: 0;
  content: "";
  left: 1.31rem;
  position: absolute;
  top: 2.7rem;
  width: 1px;
}

.execution-trace__rail {
  padding-top: var(--space-3);
  position: relative;
  z-index: 1;
}

.execution-trace__rail span {
  align-items: center;
  background: var(--color-page);
  border: 2px solid var(--step-accent);
  border-radius: 50%;
  color: var(--color-text-subtle);
  display: flex;
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-bold);
  height: 2.1rem;
  justify-content: center;
  width: 2.1rem;
}

.execution-action {
  border-bottom: 1px solid var(--color-border);
  border-left: 3px solid var(--step-accent);
  min-width: 0;
}

.execution-action--allow {
  --step-accent: var(--color-success);
}

.execution-action--ask {
  --step-accent: var(--color-warning);
}

.execution-action--deny {
  --step-accent: var(--color-danger);
}

.execution-trace__step--selected .execution-action,
.execution-trace__step--current .execution-action {
  background: var(--color-row-selected);
}

.execution-action__summary {
  align-items: center;
  background: transparent;
  border: 0;
  color: var(--color-text);
  cursor: pointer;
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(14rem, 1.5fr) minmax(11rem, 1fr) auto auto auto;
  min-height: 4rem;
  padding: var(--space-2) var(--space-4);
  text-align: left;
  touch-action: manipulation;
  width: 100%;
  -webkit-tap-highlight-color: transparent;
}

.execution-action__summary:hover {
  background: var(--color-row-hover);
}

.execution-action__summary:focus-visible,
.execution-trace__search button:focus-visible,
.execution-trace__filters button:focus-visible,
.execution-trace__updates button:focus-visible,
.execution-action__actions :is(button, a):focus-visible,
.execution-action__checks summary:focus-visible,
.execution-trace__empty button:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: 2px;
}

.execution-action__identity,
.execution-action__runtime {
  align-items: center;
  display: flex;
  gap: var(--space-3);
  min-width: 0;
}

.execution-action__category-icon {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-1);
  color: var(--color-active);
  display: inline-flex;
  flex: 0 0 auto;
  height: 2rem;
  justify-content: center;
  width: 2rem;
}

.execution-action__name,
.execution-action__runtime > span {
  display: grid;
  gap: 0.1rem;
  min-width: 0;
}

.execution-action__name strong,
.execution-action__runtime strong {
  overflow-wrap: anywhere;
}

.execution-action__name code,
.execution-action__name small,
.execution-action__runtime small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-action__name code {
  font-family: var(--font-family-mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.execution-action__runtime > svg {
  color: var(--color-active);
  flex: 0 0 auto;
}

.execution-action__runtime > svg.is-running {
  animation: execution-spin 1.1s linear infinite;
}

.execution-action__current {
  color: var(--color-active-strong);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.execution-action__chevron {
  color: var(--color-text-subtle);
  transition: transform var(--transition-fast);
}

.execution-action__chevron.is-open {
  transform: rotate(180deg);
}

.execution-action__detail {
  background: var(--color-surface-muted);
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-4);
  padding: var(--space-4);
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
  display: grid;
  gap: var(--space-1);
}

.execution-action__reason strong,
.execution-action__events h4 {
  font-size: var(--font-size-12);
}

.execution-action__reason span {
  color: var(--color-text-muted);
  overflow-wrap: anywhere;
}

.execution-action__events {
  display: grid;
  gap: var(--space-2);
}

.execution-action__events h4 {
  margin: 0;
}

.execution-action__events ol,
.execution-action__checks ol {
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}

.execution-action__events li {
  align-items: baseline;
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 10rem minmax(0, 1fr) auto;
  padding: var(--space-2) 0;
}

.execution-action__events time,
.execution-action__events small,
.execution-action__checks time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-variant-numeric: tabular-nums;
}

.execution-action__checks summary {
  color: var(--color-link);
  cursor: pointer;
  font-weight: var(--font-weight-semibold);
}

.execution-action__checks ol {
  padding-top: var(--space-2);
}

.execution-action__checks li {
  align-items: start;
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: auto 10rem minmax(0, 1fr);
  padding: var(--space-2) 0;
}

.execution-action__actions {
  align-items: center;
  border-top: 1px solid var(--color-border);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  padding-top: var(--space-3);
}

.execution-action__actions :is(button, a):hover,
.execution-trace__filters button:hover,
.execution-trace__updates button:hover,
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
  border-block: 1px dashed var(--color-border-strong);
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

@media (max-width: 70rem) {
  .execution-action__summary {
    grid-template-columns: minmax(13rem, 1.4fr) minmax(10rem, 1fr) auto auto;
  }

  .execution-action__current {
    display: none;
  }
}

@media (max-width: 62rem) {
  .execution-action__summary {
    grid-template-columns: minmax(0, 1fr) auto auto;
  }

  .execution-action__runtime {
    grid-column: 1 / -1;
    grid-row: 2;
  }

  .execution-action__facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 44rem) {
  .execution-trace__header,
  .execution-trace__updates {
    align-items: start;
    flex-direction: column;
  }

  .execution-trace__summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .execution-trace__summary > div:nth-child(3) {
    border-left: 0;
  }

  .execution-trace__step {
    grid-template-columns: 2.35rem minmax(0, 1fr);
  }

  .execution-trace__step:not(:last-child)::before {
    left: 1rem;
  }

  .execution-trace__rail span {
    height: 1.85rem;
    width: 1.85rem;
  }

  .execution-action__summary {
    gap: var(--space-2);
    grid-template-columns: minmax(0, 1fr) auto;
    padding-inline: var(--space-3);
  }

  .execution-action__summary > :deep(.status-badge) {
    grid-column: 1;
    justify-self: start;
  }

  .execution-action__chevron {
    grid-column: 2;
    grid-row: 1;
  }

  .execution-action__facts,
  .execution-action__events li,
  .execution-action__checks li,
  .execution-trace__empty {
    grid-template-columns: 1fr;
  }
}

@media (prefers-reduced-motion: reduce) {
  .execution-action__runtime > svg.is-running {
    animation: none;
  }

  .execution-action__chevron {
    transition: none;
  }
}
</style>
