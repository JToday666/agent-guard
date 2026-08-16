<template>
  <ol class="execution-list" aria-label="按审计顺序排列的运行步骤">
    <li
      v-for="step in steps"
      :key="step.stepId"
      class="execution-list__item"
      :class="[
        `execution-list__item--${step.decision}`,
        {
          'execution-list__item--current': step.stepId === currentStepId,
          'execution-list__item--selected': step.stepId === selectedStepId,
          'execution-list__item--updated': updatedStepIds.has(step.stepId),
        },
      ]"
      :data-action-id="step.actionId ?? undefined"
      :data-step-id="step.stepId"
    >
      <button type="button" @click="handleSelect(step)">
        <span class="execution-list__rail" aria-hidden="true">
          {{ String(stepNumber(step)).padStart(2, "0") }}
        </span>
        <span class="execution-list__identity">
          <span class="execution-list__category-icon" aria-hidden="true">
            <component :is="categoryIcon(step.category)" :size="17" />
          </span>
          <span>
            <strong>{{ step.displayName }}</strong>
            <code v-if="step.actionName" translate="no">{{ step.actionName }}</code>
            <small v-else>{{ getExecutionCategoryLabel(step.category) }}</small>
          </span>
        </span>
        <span class="execution-list__resource">
          <small>资源目标</small>
          <span>{{ step.resourceSummary ?? "未记录" }}</span>
        </span>
        <ExecutionSupervisionCapsules v-if="step.kind === 'action'" density="list" :step="step" />
        <span v-else class="execution-list__runtime">
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
        <span v-if="step.stepId === currentStepId" class="execution-list__current">当前</span>
        <ChevronRight :size="16" aria-hidden="true" />
      </button>
    </li>
  </ol>
</template>

<script setup lang="ts">
import {
  Activity,
  Ban,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  CircleX,
  Clock3,
  Database,
  FileCheck2,
  Layers3,
  LoaderCircle,
  MessageSquare,
  ShieldCheck,
  Wrench,
} from "@lucide/vue";
import type { Component } from "vue";

import {
  getExecutionApprovalLabel,
  getExecutionCategoryLabel,
} from "../../data/evidence/execution-trace";
import type {
  ExecutionStepCategory,
  ExecutionStepViewModel,
  TraceLifecycleState,
} from "../../types/dashboard";
import ExecutionSupervisionCapsules from "./ExecutionSupervisionCapsules.vue";

defineOptions({ name: "ExecutionTraceList" });

const props = defineProps<{
  currentStepId?: string;
  lifecycleState: TraceLifecycleState;
  selectedStepId?: string;
  stepNumberById: ReadonlyMap<string, number>;
  steps: readonly ExecutionStepViewModel[];
  updatedStepIds: ReadonlySet<string>;
}>();

const emit = defineEmits<{
  interaction: [];
  select: [step: ExecutionStepViewModel];
}>();

function stepNumber(step: ExecutionStepViewModel): number {
  return props.stepNumberById.get(step.stepId) ?? 1;
}

function handleSelect(step: ExecutionStepViewModel): void {
  emit("interaction");
  emit("select", step);
}

function displayStatus(step: ExecutionStepViewModel): string {
  const isTerminal = ["completed", "failed", "cancelled"].includes(props.lifecycleState);
  if (!isTerminal || step.settled) return step.statusLabel;
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
</script>

<style scoped lang="scss">
.execution-list {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  list-style: none;
  margin: 0;
  overflow: hidden;
  padding: 0;
}

.execution-list__item {
  --step-accent: var(--color-border-strong);
  content-visibility: auto;
  contain-intrinsic-size: auto 4.5rem;
}

.execution-list__item + .execution-list__item {
  border-top: 1px solid var(--color-border);
}

.execution-list__item--allow {
  --step-accent: var(--color-success);
}

.execution-list__item--ask {
  --step-accent: var(--color-warning);
}

.execution-list__item--deny {
  --step-accent: var(--color-danger);
}

.execution-list__item > button {
  align-items: center;
  background: var(--color-surface);
  border: 0;
  border-left: 3px solid var(--step-accent);
  color: var(--color-text);
  display: grid;
  gap: var(--space-3);
  grid-template-columns:
    2.25rem minmax(11rem, 1fr) minmax(8rem, 0.65fr) minmax(24rem, 1.55fr)
    auto auto;
  min-height: 4.5rem;
  padding: var(--space-2) var(--space-3);
  text-align: left;
  width: 100%;
}

.execution-list__item > button:hover {
  background: var(--color-row-hover);
}

.execution-list__item--selected > button,
.execution-list__item--current > button {
  background: var(--color-row-selected);
}

.execution-list__item--updated > button {
  box-shadow: inset 0 0 0 1px var(--color-active-border);
}

.execution-list__rail {
  align-items: center;
  border: 2px solid var(--step-accent);
  border-radius: 50%;
  color: var(--color-text-subtle);
  display: flex;
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  height: 2rem;
  justify-content: center;
  width: 2rem;
}

.execution-list__identity,
.execution-list__runtime {
  align-items: center;
  display: flex;
  gap: var(--space-3);
  min-width: 0;
}

.execution-list__identity > span:last-child,
.execution-list__runtime > span {
  display: grid;
  gap: 0.1rem;
  min-width: 0;
}

.execution-list__category-icon {
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

.execution-list__identity code,
.execution-list__identity small,
.execution-list__runtime small,
.execution-list__resource small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-list__identity code,
.execution-list__resource span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.execution-list__resource {
  display: grid;
  min-width: 0;
}

.execution-list__runtime > svg {
  color: var(--color-active);
  flex: 0 0 auto;
}

.execution-list__runtime > svg.is-running {
  animation: execution-list-spin 1.1s linear infinite;
}

.execution-list__current {
  color: var(--color-active-strong);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.execution-list__item > button > svg {
  color: var(--color-text-subtle);
}

@keyframes execution-list-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 72rem) {
  .execution-list__item > button {
    grid-template-columns: 2.25rem minmax(10rem, 0.85fr) minmax(20rem, 1.5fr) auto;
  }

  .execution-list__resource,
  .execution-list__current {
    display: none;
  }
}

@media (max-width: 48rem) {
  .execution-list__item > button {
    align-items: start;
    grid-template-columns: 2.25rem minmax(0, 1fr) auto;
  }

  .execution-list__item > button > :deep(.supervision-capsules) {
    grid-column: 2 / -1;
    width: 100%;
  }

  .execution-list__runtime {
    grid-column: 2 / -1;
  }
}

@media (prefers-reduced-motion: reduce) {
  .execution-list__runtime > svg.is-running {
    animation: none;
  }
}
</style>
