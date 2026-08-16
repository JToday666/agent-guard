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
        <p>查看每个运行步骤的安全判断、人工审批与执行结果。</p>
      </div>

      <div class="execution-trace__header-side">
        <div class="execution-trace__connection" :class="`is-${pollingState.status}`">
          <component :is="connectionIcon" :size="16" aria-hidden="true" />
          <span>{{ connectionLabel }}</span>
          <button
            v-if="!isTerminal"
            type="button"
            :aria-pressed="isFollowingLatest"
            @click="toggleFollowing"
          >
            {{ isFollowingLatest ? "暂停跟随" : "恢复跟随" }}
          </button>
        </div>

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
      </div>
    </header>

    <p v-if="isWindowPartial" class="execution-trace__window-note">
      当前只展示已加载审计窗口中的运行步骤，较早的动作起点可能未包含在本次响应中。
    </p>

    <ExecutionTraceToolbar
      v-if="trace.steps.length"
      :active-filter="activeFilter"
      :filter-options="filterOptions"
      :layout="layout"
      :result-count="filteredSteps.length"
      :search-query="searchQuery"
      :total-count="trace.steps.length"
      @update:active-filter="activeFilter = $event"
      @update:layout="handleLayoutChange"
      @update:search-query="searchQuery = $event"
    />

    <div v-if="pendingUpdateCount" class="execution-trace__updates">
      <span>运行轨迹有 {{ pendingUpdateCount }} 个新增或更新步骤</span>
      <button type="button" @click="showLatestUpdate">
        <ArrowDownToLine :size="15" aria-hidden="true" />
        查看最新
      </button>
    </div>
    <span class="sr-only" aria-live="polite">{{ priorityAnnouncement }}</span>

    <div v-if="trace.steps.length" class="execution-trace__workbench">
      <div class="execution-trace__primary">
        <ExecutionFlowGraph
          v-if="layout === 'graph'"
          :key="traceId"
          ref="flowGraphRef"
          :current-step-id="currentStepId"
          :lifecycle-state="trace.lifecycleState"
          :matching-step-ids="matchingStepIds"
          :selected-step-id="selectedStep?.stepId"
          :steps="trace.steps"
          :trace-id="traceId"
          :updated-step-ids="pendingUpdateStepIds"
          @interaction="pauseFollowing"
          @select="handleSelectStep"
        />

        <template v-else>
          <ExecutionTraceList
            v-if="filteredSteps.length"
            :current-step-id="currentStepId"
            :lifecycle-state="trace.lifecycleState"
            :selected-step-id="selectedStep?.stepId"
            :step-number-by-id="stepNumberById"
            :steps="filteredSteps"
            :updated-step-ids="pendingUpdateStepIds"
            @interaction="pauseFollowing"
            @select="handleSelectStep"
          />
          <div v-else class="execution-trace__empty">
            <ListFilter :size="22" aria-hidden="true" />
            <div>
              <strong>当前条件没有匹配步骤</strong>
              <p>清除搜索或恢复全部筛选后继续查看。</p>
            </div>
            <button type="button" @click="resetFilters">恢复全部步骤</button>
          </div>
        </template>
      </div>

      <ExecutionStepInspector
        :approval-basis="selectedApprovalBasis"
        :lifecycle-state="trace.lifecycleState"
        :step="selectedStep"
        :step-number="selectedStepNumber"
        @select-event="emit('select-event', $event)"
        @show-provenance="emit('show-provenance', $event)"
      />
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
  ArrowDownToLine,
  CheckCircle2,
  CircleDashed,
  ListFilter,
  PauseCircle,
  Wifi,
  WifiOff,
} from "@lucide/vue";
import { computed, defineAsyncComponent, nextTick, ref, watch } from "vue";

import type {
  ExecutionStepFilter,
  ExecutionTraceLayout,
} from "../../data/evidence/execution-flow-layout";
import type {
  ExecutionStepViewModel,
  ExecutionTraceViewModel,
  TracePollingState,
} from "../../types/dashboard";
import type { ApprovalBasisViewModel } from "../../types/runtime-supervision";
import ExecutionStepInspector from "./ExecutionStepInspector.vue";
import ExecutionTraceList from "./ExecutionTraceList.vue";
import ExecutionTraceToolbar from "./ExecutionTraceToolbar.vue";

defineOptions({ name: "ExecutionTrace" });

const ExecutionFlowGraph = defineAsyncComponent(() => import("./ExecutionFlowGraph.vue"));

const props = defineProps<{
  traceId: string;
  trace: ExecutionTraceViewModel;
  pollingState: TracePollingState;
  layout: ExecutionTraceLayout;
  approvalBasisById?: Readonly<Record<string, ApprovalBasisViewModel>>;
  isWindowPartial?: boolean;
  selectedActionId?: string;
  selectedAuditId?: string;
}>();

const emit = defineEmits<{
  "layout-change": [layout: ExecutionTraceLayout];
  "select-event": [auditId: string];
  "select-step": [step: ExecutionStepViewModel];
  "show-audit": [];
  "show-provenance": [step: ExecutionStepViewModel];
}>();

const flowGraphRef = ref<{
  fitCanvas: () => Promise<void>;
  focusStep: (stepId: string) => Promise<void>;
} | null>(null);
const activeFilter = ref<ExecutionStepFilter>("all");
const isFollowingLatest = ref(true);
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
const riskStepCount = computed(() => props.trace.steps.filter(isRiskStep).length);
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
const explicitSelectedStep = computed(() => props.trace.steps.find(isSelected));
const selectedStep = computed(
  () =>
    explicitSelectedStep.value ??
    props.trace.steps.find((step) => step.stepId === currentStepId.value) ??
    props.trace.steps.at(-1),
);
const selectedStepNumber = computed(() => {
  if (!selectedStep.value) return undefined;
  return stepNumberById.value.get(selectedStep.value.stepId);
});
const selectedApprovalBasis = computed(() => {
  const approvalId = selectedStep.value?.approvalId;
  return approvalId ? props.approvalBasisById?.[approvalId] : undefined;
});
const stepNumberById = computed(
  () => new Map(props.trace.steps.map((step, index) => [step.stepId, index + 1])),
);

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

const filteredSteps = computed(() => {
  const query = searchQuery.value.trim().toLocaleLowerCase();
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

const matchingStepIds = computed(
  () => new Set(filteredSteps.value.map((step) => step.stepId)) as ReadonlySet<string>,
);

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
      isFollowingLatest.value = true;
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
    const priorityChanges = changed.filter(
      (step) =>
        step.approval === "pending" || step.decision === "deny" || step.execution === "failed",
    );
    priorityAnnouncement.value = priorityChanges.length
      ? `有 ${priorityChanges.length} 个需要关注的运行步骤发生变化。`
      : "";

    if (isFollowingLatest.value && props.layout === "graph") {
      const latest = changed.at(-1);
      if (latest) void nextTick().then(() => flowGraphRef.value?.focusStep(latest.stepId));
    }
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
    step.supervision.activityState,
    step.supervision.enforcement.gateState,
    step.supervision.controlIntegrity.status,
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

function isSelected(step: ExecutionStepViewModel): boolean {
  return Boolean(
    (props.selectedActionId && step.actionId === props.selectedActionId) ||
    (props.selectedAuditId && step.auditIds.includes(props.selectedAuditId)),
  );
}

function handleSelectStep(step: ExecutionStepViewModel): void {
  pauseFollowing();
  markStepSeen(step.stepId);
  emit("select-step", step);
}

function handleLayoutChange(nextLayout: ExecutionTraceLayout): void {
  emit("layout-change", nextLayout);
}

function pauseFollowing(): void {
  if (!isTerminal.value) isFollowingLatest.value = false;
}

function toggleFollowing(): void {
  isFollowingLatest.value = !isFollowingLatest.value;
  if (isFollowingLatest.value) void showLatestUpdate();
}

function markStepSeen(stepId: string): void {
  if (!pendingUpdateStepIds.value.has(stepId)) return;
  const next = new Set(pendingUpdateStepIds.value);
  next.delete(stepId);
  pendingUpdateStepIds.value = next;
  if (!next.size) priorityAnnouncement.value = "";
}

async function showLatestUpdate(): Promise<void> {
  const latest =
    [...props.trace.steps].reverse().find((step) => pendingUpdateStepIds.value.has(step.stepId)) ??
    props.trace.steps.at(-1);
  if (!latest) return;
  activeFilter.value = "all";
  searchQuery.value = "";
  isFollowingLatest.value = true;
  pendingUpdateStepIds.value = new Set();
  priorityAnnouncement.value = "";
  emit("select-step", latest);
  await nextTick();
  if (props.layout === "graph") {
    await flowGraphRef.value?.focusStep(latest.stepId);
    return;
  }
  document
    .querySelector<HTMLElement>(`[data-step-id="${CSS.escape(latest.stepId)}"]`)
    ?.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "center" });
}

function resetFilters(): void {
  activeFilter.value = "all";
  searchQuery.value = "";
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
  padding: var(--space-2) var(--space-4);
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
  display: flex;
  flex: 0 0 auto;
  flex-wrap: wrap;
  font-size: var(--font-size-12);
  gap: var(--space-2);
  justify-content: flex-end;
}

.execution-trace__header-side {
  display: grid;
  flex: 0 1 38rem;
  gap: var(--space-2);
  min-width: 30rem;
}

.execution-trace__connection.is-backoff {
  color: var(--color-danger);
}

.execution-trace__connection button,
.execution-trace__updates button,
.execution-trace__empty button {
  align-items: center;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-link);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-2);
  justify-content: center;
  min-height: 2.375rem;
  padding: 0 var(--space-3);
}

.execution-trace__connection button[aria-pressed="true"] {
  background: var(--color-active-soft);
  border-color: var(--color-active-border);
  color: var(--color-active-strong);
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
  padding: 0 var(--space-3);
}

.execution-trace__summary > div:first-child {
  border-left: 0;
}

.execution-trace__summary dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-trace__summary dd {
  font-size: var(--font-size-16);
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

.execution-trace__workbench {
  align-items: start;
  display: grid;
  gap: var(--space-4);
  grid-template-columns: minmax(0, 1fr) minmax(17rem, 19rem);
  min-width: 0;
}

.execution-trace__primary {
  min-width: 0;
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

@media (max-width: 82rem) {
  .execution-trace__workbench {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 48rem) {
  .execution-trace__header,
  .execution-trace__updates {
    align-items: start;
    flex-direction: column;
  }

  .execution-trace__header-side {
    flex: auto;
    min-width: 0;
    width: 100%;
  }

  .execution-trace__connection {
    justify-content: flex-start;
  }

  .execution-trace__summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .execution-trace__summary > div:nth-child(3) {
    border-left: 0;
  }

  .execution-trace__empty {
    grid-template-columns: 1fr;
  }
}
</style>
