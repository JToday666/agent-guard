<template>
  <section
    ref="workbenchRef"
    class="execution-flow"
    :class="{
      'execution-flow--compact': isCompact,
      'execution-flow--fullscreen': isFullscreen,
      'execution-flow--sparse': steps.length <= 3,
    }"
    aria-label="执行轨迹图"
  >
    <header class="execution-flow__toolbar">
      <div>
        <strong>运行步骤视图</strong>
        <span>
          {{
            steps.length > 80
              ? "大轨迹已定位当前步骤，可通过缩略图查看全局"
              : "连线仅表示记录先后，不代表因果依赖"
          }}
        </span>
      </div>
      <div aria-label="执行轨迹图视图控制">
        <button type="button" title="缩小" aria-label="缩小执行轨迹图" @click="zoomOutCanvas">
          <Minus :size="15" aria-hidden="true" />
        </button>
        <button type="button" title="放大" aria-label="放大执行轨迹图" @click="zoomInCanvas">
          <Plus :size="15" aria-hidden="true" />
        </button>
        <button type="button" title="适配全部步骤" @click="fitCanvas">
          <Scan :size="15" aria-hidden="true" />
          适配
        </button>
        <button
          type="button"
          :title="isFullscreen ? '退出全屏' : '全屏查看'"
          @click="toggleFullscreen"
        >
          <Minimize2 v-if="isFullscreen" :size="15" aria-hidden="true" />
          <Maximize2 v-else :size="15" aria-hidden="true" />
          {{ isFullscreen ? "退出" : "全屏" }}
        </button>
      </div>
    </header>

    <div class="execution-flow__canvas" @pointerdown.capture="emit('interaction')">
      <VueFlow
        v-if="hasMeasured"
        :id="flowId"
        :nodes="flowNodes"
        :edges="flowEdges"
        :fit-view-on-init="false"
        :nodes-connectable="false"
        :nodes-draggable="false"
        :elements-selectable="true"
        :only-render-visible-elements="steps.length > 60"
        :min-zoom="steps.length > 80 ? 0.02 : 0.25"
        :max-zoom="1.7"
        :prevent-scrolling="isFullscreen"
        :zoom-on-scroll="isFullscreen"
        :pan-on-drag="true"
        class="execution-flow__vue-flow"
        @pane-ready="handleFlowReady"
        @node-click="handleNodeClick"
      >
        <Background pattern-color="var(--color-chart-grid)" :gap="22" :size="1" />
        <Controls :show-interactive="false" position="bottom-left" />
        <MiniMap
          v-if="steps.length > 6"
          :node-color="miniMapNodeColor"
          :node-stroke-color="miniMapNodeStrokeColor"
          :pannable="true"
          :zoomable="true"
          :width="154"
          :height="92"
          mask-color="var(--color-provenance-mask)"
          mask-stroke-color="var(--color-active)"
          aria-label="执行轨迹图缩略导航"
          position="bottom-right"
        />

        <template #node-execution-lane="{ data }">
          <div class="execution-lane" aria-hidden="true">
            <strong>{{ data.label }}</strong>
            <span>{{ data.description }}</span>
            <b>{{ data.count }}</b>
          </div>
        </template>

        <template #node-execution-step="{ data }">
          <article
            class="execution-node"
            :class="[
              `execution-node--${data.step.decision}`,
              {
                'execution-node--current': data.current,
                'execution-node--dimmed': !data.matched,
                'execution-node--selected': data.selected,
                'execution-node--updated': data.updated,
              },
            ]"
            :aria-label="`${data.orderLabel}：${data.step.displayName}，${getDecisionLabel(data.step.decision)}，${displayStatus(data.step)}`"
            :aria-pressed="data.selected"
            :data-action-id="data.step.actionId ?? undefined"
            :data-step-id="data.step.stepId"
            role="button"
            tabindex="0"
            @keydown.enter.stop.prevent="selectStep(data.step)"
            @keydown.space.stop.prevent="selectStep(data.step)"
          >
            <Handle
              type="target"
              :position="isCompact ? Position.Top : Position.Left"
              :connectable="false"
            />
            <header>
              <span>{{ data.orderLabel }}</span>
              <small>{{ getExecutionCategoryLabel(data.step.category) }}</small>
              <b v-if="data.current">当前</b>
            </header>
            <div class="execution-node__identity">
              <span aria-hidden="true">
                <component :is="categoryIcon(data.step.category)" :size="16" />
              </span>
              <div>
                <strong>{{ data.step.displayName }}</strong>
                <code v-if="data.step.actionName" translate="no">{{ data.step.actionName }}</code>
              </div>
            </div>
            <p :title="data.step.resourceSummary ?? '未记录资源目标'">
              {{ data.step.resourceSummary ?? "未记录资源目标" }}
            </p>
            <footer>
              <span :class="`execution-node__decision--${data.step.decision}`">
                {{ getDecisionLabel(data.step.decision) }}
              </span>
              <span class="execution-node__runtime">
                <component
                  :is="runtimeIcon(data.step)"
                  :class="{ 'is-running': data.step.phase === 'waiting_receipt' }"
                  :size="14"
                  aria-hidden="true"
                />
                {{ displayStatus(data.step) }}
              </span>
            </footer>
            <Handle
              type="source"
              :position="isCompact ? Position.Bottom : Position.Right"
              :connectable="false"
            />
          </article>
        </template>
      </VueFlow>
      <div v-else class="execution-flow__preparing" role="status">正在准备运行视图…</div>

      <div v-if="matchingStepIds.size === 0" class="execution-flow__no-match" role="status">
        当前条件没有匹配步骤，图中保留完整顺序作为上下文。
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import {
  Activity,
  Ban,
  BrainCircuit,
  CheckCircle2,
  CircleDashed,
  CircleX,
  Clock3,
  Database,
  FileCheck2,
  Layers3,
  LoaderCircle,
  Maximize2,
  MessageSquare,
  Minimize2,
  Minus,
  Plus,
  Scan,
  ShieldCheck,
  Wrench,
} from "@lucide/vue";
import { Background } from "@vue-flow/background";
import { Controls } from "@vue-flow/controls";
import {
  Handle,
  MarkerType,
  Position,
  VueFlow,
  type Edge,
  type Node,
  useVueFlow,
} from "@vue-flow/core";
import { MiniMap } from "@vue-flow/minimap";
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch, type Component } from "vue";

import {
  buildExecutionFlowLayout,
  EXECUTION_FLOW_NODE_HEIGHT,
  EXECUTION_FLOW_NODE_WIDTH,
  type ExecutionFlowOrientation,
} from "../../data/evidence/execution-flow-layout";
import { getExecutionCategoryLabel } from "../../data/evidence/execution-trace";
import type {
  ExecutionStepCategory,
  ExecutionStepViewModel,
  TraceLifecycleState,
} from "../../types/dashboard";
import { getDecisionLabel } from "../../utils/dashboard-formatters";

defineOptions({ name: "ExecutionFlowGraph" });

interface ExecutionFlowNodeData {
  current: boolean;
  matched: boolean;
  orderLabel: string;
  selected: boolean;
  step: ExecutionStepViewModel;
  updated: boolean;
}

const props = defineProps<{
  currentStepId?: string;
  lifecycleState: TraceLifecycleState;
  matchingStepIds: ReadonlySet<string>;
  selectedStepId?: string;
  steps: readonly ExecutionStepViewModel[];
  traceId: string;
  updatedStepIds: ReadonlySet<string>;
}>();

const emit = defineEmits<{
  interaction: [];
  select: [step: ExecutionStepViewModel];
}>();

const flowId = `execution-flow-${props.traceId}`;
const workbenchRef = ref<HTMLElement | null>(null);
const isCompact = ref(false);
const isFullscreen = ref(false);
const hasMeasured = ref(false);
const prefersReducedMotion = ref(false);
const isFlowReady = ref(false);
let resizeObserver: ResizeObserver | null = null;
let motionMedia: MediaQueryList | null = null;
let readyFrame = 0;
let previousBodyOverflow = "";

const { viewportHelper } = useVueFlow(flowId);
const orientation = computed<ExecutionFlowOrientation>(() =>
  isCompact.value ? "vertical" : "horizontal",
);
const layout = computed(() => buildExecutionFlowLayout(props.steps, orientation.value));

const flowNodes = computed<Node[]>(() => {
  const laneNodes: Node[] = layout.value.lanes.map((lane) => ({
    ariaLabel: `${lane.label}，${lane.count} 个步骤`,
    data: lane,
    draggable: false,
    id: `lane:${lane.id}`,
    position: lane.position,
    selectable: false,
    style: {
      height: `${lane.height}px`,
      width: `${lane.width}px`,
      zIndex: 0,
    },
    type: "execution-lane",
  }));
  const stepNodes: Node<ExecutionFlowNodeData>[] = layout.value.nodes.map((node) => ({
    ariaLabel: `${String(node.order + 1).padStart(2, "0")}：${node.step.displayName}`,
    class: props.matchingStepIds.has(node.id)
      ? "execution-flow-node--matched"
      : "execution-flow-node--dimmed",
    data: {
      current: node.id === props.currentStepId,
      matched: props.matchingStepIds.has(node.id),
      orderLabel: String(node.order + 1).padStart(2, "0"),
      selected: node.id === props.selectedStepId,
      step: node.step,
      updated: props.updatedStepIds.has(node.id),
    },
    draggable: false,
    height: EXECUTION_FLOW_NODE_HEIGHT,
    id: node.id,
    position: node.position,
    selectable: true,
    style: { zIndex: 2 },
    type: "execution-step",
    width: EXECUTION_FLOW_NODE_WIDTH,
  }));
  return [...laneNodes, ...stepNodes];
});

const flowEdges = computed<Edge[]>(() =>
  layout.value.edges.map((edge) => ({
    animated: edge.target === props.currentStepId && !prefersReducedMotion.value,
    ariaLabel: `${edge.label}：从 ${edge.source} 到 ${edge.target}`,
    class:
      props.matchingStepIds.has(edge.source) && props.matchingStepIds.has(edge.target)
        ? "execution-order-edge"
        : "execution-order-edge execution-order-edge--dimmed",
    id: edge.id,
    label: props.steps.length <= 40 ? edge.label : undefined,
    labelBgBorderRadius: 3,
    labelBgPadding: [4, 2],
    labelBgStyle: {
      fill: "var(--color-surface)",
      fillOpacity: 0.94,
    },
    labelStyle: {
      fill: "var(--color-text-subtle)",
      fontSize: 10,
      fontWeight: 600,
    },
    markerEnd: MarkerType.ArrowClosed,
    source: edge.source,
    target: edge.target,
    type: "smoothstep",
  })),
);

function handleFlowReady(): void {
  scheduleFlowReady();
}

function scheduleFlowReady(attempt = 0): void {
  window.cancelAnimationFrame(readyFrame);
  readyFrame = window.requestAnimationFrame(() => {
    if (viewportHelper.value.viewportInitialized) {
      readyFrame = window.requestAnimationFrame(() => {
        if (!viewportHelper.value.viewportInitialized) {
          scheduleFlowReady(attempt + 1);
          return;
        }
        isFlowReady.value = true;
        void nextTick().then(initializeCanvas);
      });
      return;
    }
    if (attempt < 8) scheduleFlowReady(attempt + 1);
  });
}

async function initializeCanvas(): Promise<void> {
  if (props.steps.length <= 80) {
    await fitCanvas();
    return;
  }
  const focusId = props.selectedStepId || props.currentStepId || props.steps.at(-1)?.stepId;
  if (focusId) await focusStep(focusId);
}

function handleNodeClick(event: { node: Node }): void {
  if (event.node.type !== "execution-step") return;
  const step = props.steps.find((item) => item.stepId === event.node.id);
  if (step) selectStep(step);
}

function selectStep(step: ExecutionStepViewModel): void {
  emit("interaction");
  emit("select", step);
}

async function fitCanvas(): Promise<void> {
  const viewport = viewportHelper.value;
  if (!isFlowReady.value || !viewport.viewportInitialized || !props.steps.length) return;
  await viewport.fitView({
    duration: prefersReducedMotion.value ? 0 : 180,
    maxZoom: 1,
    padding: isFullscreen.value ? 0.08 : 0.12,
  });
}

async function focusStep(stepId: string): Promise<void> {
  const node = layout.value.nodes.find((item) => item.id === stepId);
  const viewport = viewportHelper.value;
  if (!node || !isFlowReady.value || !viewport.viewportInitialized) return;
  await viewport.setCenter(
    node.position.x + EXECUTION_FLOW_NODE_WIDTH / 2,
    node.position.y + EXECUTION_FLOW_NODE_HEIGHT / 2,
    {
      duration: prefersReducedMotion.value ? 0 : 180,
      zoom: 1,
    },
  );
}

function zoomInCanvas(): void {
  const viewport = viewportHelper.value;
  if (!viewport.viewportInitialized) return;
  void viewport.zoomIn({ duration: prefersReducedMotion.value ? 0 : 120 });
}

function zoomOutCanvas(): void {
  const viewport = viewportHelper.value;
  if (!viewport.viewportInitialized) return;
  void viewport.zoomOut({ duration: prefersReducedMotion.value ? 0 : 120 });
}

async function toggleFullscreen(): Promise<void> {
  isFullscreen.value = !isFullscreen.value;
  await nextTick();
  await fitCanvas();
}

function handleEscape(event: KeyboardEvent): void {
  if (event.key !== "Escape" || !isFullscreen.value) return;
  isFullscreen.value = false;
  void nextTick().then(fitCanvas);
}

function updateMotionPreference(): void {
  prefersReducedMotion.value = motionMedia?.matches ?? false;
}

function displayStatus(step: ExecutionStepViewModel): string {
  const isTerminal = ["completed", "failed", "cancelled"].includes(props.lifecycleState);
  if (!isTerminal || step.settled) return step.statusLabel;
  if (step.approval === "pending") return "审批结果未确认";
  if (step.receiptExpectation === "required") return "执行结果未确认";
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

function miniMapNodeColor(node: Node): string {
  if (node.type === "execution-lane") return "transparent";
  const step = props.steps.find((item) => item.stepId === node.id);
  if (step?.decision === "allow") return "var(--color-success)";
  if (step?.decision === "ask") return "var(--color-warning)";
  if (step?.decision === "deny") return "var(--color-danger)";
  return "var(--color-chart-slate)";
}

function miniMapNodeStrokeColor(node: Node): string {
  return node.id === props.selectedStepId ? "var(--color-active)" : "var(--color-border-strong)";
}

watch(orientation, async () => {
  await nextTick();
  await initializeCanvas();
});

watch(
  () => props.steps.map((step) => step.stepId).join("\u0000"),
  async (ids, previousIds) => {
    if (!previousIds || ids === previousIds) return;
    await nextTick();
    if (props.steps.length <= 1) await fitCanvas();
  },
);

watch(
  () => props.selectedStepId,
  (stepId) => {
    if (stepId) void nextTick().then(() => focusStep(stepId));
  },
);

watch(isFullscreen, (fullscreen) => {
  if (fullscreen) {
    previousBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return;
  }
  document.body.style.overflow = previousBodyOverflow;
});

onMounted(() => {
  resizeObserver = new ResizeObserver(([entry]) => {
    isCompact.value = (entry?.contentRect.width ?? 0) < 920;
    hasMeasured.value = true;
  });
  if (workbenchRef.value) resizeObserver.observe(workbenchRef.value);
  motionMedia = window.matchMedia("(prefers-reduced-motion: reduce)");
  motionMedia.addEventListener("change", updateMotionPreference);
  updateMotionPreference();
  window.addEventListener("keydown", handleEscape);
});

onBeforeUnmount(() => {
  window.cancelAnimationFrame(readyFrame);
  if (isFullscreen.value) document.body.style.overflow = previousBodyOverflow;
  resizeObserver?.disconnect();
  motionMedia?.removeEventListener("change", updateMotionPreference);
  window.removeEventListener("keydown", handleEscape);
});

defineExpose({ fitCanvas, focusStep });
</script>

<style>
@import "@vue-flow/core/dist/style.css";
@import "@vue-flow/core/dist/theme-default.css";
@import "@vue-flow/controls/dist/style.css";
@import "@vue-flow/minimap/dist/style.css";
</style>

<style scoped lang="scss">
.execution-flow {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  grid-template-rows: auto minmax(31rem, 60vh);
  min-width: 0;
  overflow: hidden;
}

.execution-flow--fullscreen {
  border-radius: 0;
  inset: 0;
  position: fixed;
  z-index: 90;
}

.execution-flow--sparse:not(.execution-flow--fullscreen) {
  grid-template-rows: auto 24rem;
}

.execution-flow__toolbar {
  align-items: center;
  background: var(--color-surface-muted);
  border-bottom: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
  padding: var(--space-2) var(--space-3);
}

.execution-flow__toolbar > div:first-child {
  display: grid;
  gap: 0.1rem;
}

.execution-flow__toolbar > div:first-child span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-flow__toolbar > div:last-child {
  display: flex;
  gap: var(--space-1);
}

.execution-flow__toolbar button {
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
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}

.execution-flow__toolbar button[aria-label] {
  padding: 0;
  width: 2.25rem;
}

.execution-flow__canvas {
  min-height: 0;
  min-width: 0;
  position: relative;
}

.execution-flow__vue-flow {
  background: color-mix(in srgb, var(--color-page) 76%, var(--color-surface));
}

.execution-flow__no-match {
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  left: 50%;
  padding: var(--space-2) var(--space-3);
  position: absolute;
  top: var(--space-4);
  transform: translateX(-50%);
  z-index: 5;
}

.execution-flow__preparing {
  align-items: center;
  color: var(--color-text-subtle);
  display: flex;
  font-size: var(--font-size-12);
  inset: 0;
  justify-content: center;
  position: absolute;
}

.execution-flow :deep(.vue-flow__node-execution-lane) {
  pointer-events: none;
}

.execution-lane {
  background: color-mix(in srgb, var(--color-surface-muted) 76%, transparent);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  height: 100%;
  padding: var(--space-3);
  position: relative;
  width: 100%;
}

.execution-lane strong {
  color: var(--color-active-strong);
  display: block;
  font-size: var(--font-size-12);
}

.execution-lane span {
  color: var(--color-text-subtle);
  font-size: 0.625rem;
}

.execution-lane b {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-pill);
  color: var(--color-text-subtle);
  font-size: 0.625rem;
  padding: 0.05rem var(--space-2);
  position: absolute;
  right: var(--space-3);
  top: var(--space-3);
}

.execution-node {
  --node-accent: var(--color-chart-slate);
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-left: 4px solid var(--node-accent);
  border-radius: var(--radius-2);
  box-shadow: var(--shadow-subtle);
  color: var(--color-text);
  display: grid;
  gap: var(--space-2);
  min-height: 8.625rem;
  padding: var(--space-3);
  transition:
    border-color var(--transition-fast),
    box-shadow var(--transition-fast),
    opacity var(--transition-fast);
  width: 14.75rem;
}

.execution-node--allow {
  --node-accent: var(--color-success);
}

.execution-node--ask {
  --node-accent: var(--color-warning);
}

.execution-node--deny {
  --node-accent: var(--color-danger);
}

.execution-node--selected {
  border-color: var(--color-active);
  box-shadow: var(--shadow-focus), var(--shadow-elevated);
}

.execution-node--current {
  box-shadow:
    inset 0 0 0 1px var(--color-active-border),
    var(--glow-live);
}

.execution-node--updated {
  animation: execution-node-update 900ms var(--ease-emphasis) both;
}

.execution-node--dimmed {
  opacity: 0.24;
}

.execution-node > header,
.execution-node > footer {
  align-items: center;
  display: flex;
  gap: var(--space-2);
}

.execution-node > header > span {
  color: var(--node-accent);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.execution-node > header small {
  color: var(--color-text-subtle);
  font-size: 0.625rem;
}

.execution-node > header b {
  color: var(--color-active-strong);
  font-size: 0.625rem;
  margin-left: auto;
}

.execution-node__identity {
  align-items: center;
  display: flex;
  gap: var(--space-2);
  min-width: 0;
}

.execution-node__identity > span {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-1);
  color: var(--color-active);
  display: flex;
  flex: 0 0 auto;
  height: 1.8rem;
  justify-content: center;
  width: 1.8rem;
}

.execution-node__identity > div {
  display: grid;
  min-width: 0;
}

.execution-node__identity strong,
.execution-node__identity code,
.execution-node > p {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.execution-node__identity strong {
  font-size: var(--font-size-12);
}

.execution-node__identity code,
.execution-node > p {
  color: var(--color-text-subtle);
  font-size: 0.625rem;
}

.execution-node > p {
  margin: 0;
}

.execution-node > footer {
  border-top: 1px solid var(--color-border);
  justify-content: space-between;
  padding-top: var(--space-2);
}

.execution-node > footer > span {
  font-size: 0.625rem;
  font-weight: var(--font-weight-semibold);
}

.execution-node__decision--allow {
  color: var(--color-success);
}

.execution-node__decision--ask {
  color: var(--color-warning-strong);
}

.execution-node__decision--deny {
  color: var(--color-danger);
}

.execution-node__decision--unknown {
  color: var(--color-text-subtle);
}

.execution-node__runtime {
  align-items: center;
  color: var(--color-text-muted);
  display: inline-flex;
  gap: var(--space-1);
  max-width: 8.5rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.execution-node__runtime svg {
  flex: 0 0 auto;
}

.execution-node__runtime svg.is-running {
  animation: execution-flow-spin 1.1s linear infinite;
}

.execution-flow :deep(.vue-flow__edge-path) {
  stroke: var(--color-border-strong);
  stroke-width: 1.4;
}

.execution-flow :deep(.execution-order-edge--dimmed) {
  opacity: 0.22;
}

.execution-flow :deep(.vue-flow__edge.selected .vue-flow__edge-path) {
  stroke: var(--color-active);
}

.execution-flow :deep(.vue-flow__controls),
.execution-flow :deep(.vue-flow__minimap) {
  border: 1px solid var(--color-border);
  box-shadow: var(--shadow-subtle);
}

@keyframes execution-flow-spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes execution-node-update {
  0% {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--color-active) 45%, transparent);
  }
  100% {
    box-shadow: 0 0 0 0.55rem transparent;
  }
}

@media (max-width: 68rem) {
  .execution-flow {
    grid-template-rows: auto minmax(34rem, 68vh);
  }

  .execution-flow__toolbar {
    align-items: start;
  }

  .execution-flow__toolbar > div:first-child span {
    max-width: 24rem;
  }
}

@media (prefers-reduced-motion: reduce) {
  .execution-node,
  .execution-node--updated,
  .execution-node__runtime svg.is-running {
    animation: none;
    transition: none;
  }
}
</style>
