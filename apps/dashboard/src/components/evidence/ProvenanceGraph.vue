<template>
  <div
    class="provenance-workbench"
    :aria-busy="isLayouting"
    :class="[
      `provenance-workbench--${zoomBand}`,
      {
        'provenance-workbench--compact': isCompact,
        'provenance-workbench--fullscreen': isFullscreen,
      },
    ]"
  >
    <template v-if="graph.nodes.length">
      <header class="provenance-toolbar">
        <div class="provenance-toolbar__search">
          <label class="sr-only" :for="`${flowId}-search`">搜索溯源节点</label>
          <Search :size="15" aria-hidden="true" />
          <input
            :id="`${flowId}-search`"
            v-model.trim="searchQuery"
            autocomplete="off"
            name="provenance-search"
            type="search"
            placeholder="搜索节点、摘要或状态…"
            @keydown.enter.prevent="focusSearchResult"
          />
          <button
            type="button"
            :disabled="!searchMatches.length"
            :title="
              searchMatches.length ? `定位 ${searchMatches.length} 个匹配节点` : '没有匹配节点'
            "
            @click="focusSearchResult"
          >
            定位
          </button>
        </div>

        <label class="provenance-toolbar__select">
          <span class="sr-only">节点类型筛选</span>
          <Filter :size="14" aria-hidden="true" />
          <select v-model="activeKind" aria-label="节点类型筛选" name="provenance-kind-filter">
            <option value="all">全部类型</option>
            <option v-for="option in kindOptions" :key="option.value" :value="option.value">
              {{ option.label }} · {{ option.count }}
            </option>
          </select>
        </label>

        <div class="provenance-toolbar__actions" aria-label="溯源图视图控制">
          <button
            v-if="hasCollapsibleBranches"
            type="button"
            :aria-pressed="viewMode === 'critical'"
            :title="viewMode === 'critical' ? '显示完整关系' : '仅显示关键攻击路径'"
            @click="toggleViewMode"
          >
            <Route :size="15" aria-hidden="true" />
            {{ viewMode === "critical" ? "展开旁支" : "关键路径" }}
          </button>
          <button type="button" title="缩放复位" @click="resetZoom">
            <RotateCcw :size="15" aria-hidden="true" />
            复位
          </button>
          <button type="button" title="适配全部可见节点" @click="fitCanvas">
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

      <nav class="provenance-phases" aria-label="处理阶段显示控制">
        <button
          v-for="phase in phaseOptions"
          :key="phase.id"
          type="button"
          :aria-pressed="!collapsedPhases.has(phase.id)"
          :class="{ 'provenance-phases__item--collapsed': collapsedPhases.has(phase.id) }"
          :title="
            collapsedPhases.has(phase.id)
              ? `展开${phase.title}，含 ${phase.count} 个节点`
              : `收拢${phase.title}`
          "
          @click="togglePhase(phase.id)"
        >
          <span>{{ phase.index }}</span>
          <strong>{{ phase.title }}</strong>
          <b>{{ phase.count }}</b>
        </button>
      </nav>

      <div class="provenance-canvas">
        <VueFlow
          :id="flowId"
          :nodes="flowNodes"
          :edges="flowEdges"
          :fit-view-on-init="false"
          :nodes-connectable="false"
          :nodes-draggable="false"
          :elements-selectable="true"
          :only-render-visible-elements="flowNodes.length > 40"
          :min-zoom="0.2"
          :max-zoom="1.8"
          :prevent-scrolling="isFullscreen"
          :zoom-on-scroll="isFullscreen"
          :pan-on-drag="true"
          class="provenance-flow"
          @edge-mouse-enter="handleEdgeMouseEnter"
          @edge-mouse-leave="handleEdgeMouseLeave"
          @node-click="handleNodeClick"
          @viewport-change="handleViewportChange"
        >
          <Background pattern-color="var(--color-chart-grid)" :gap="22" :size="1" />
          <Controls :show-interactive="false" position="bottom-left" />
          <MiniMap
            :node-color="miniMapNodeColor"
            :node-stroke-color="miniMapNodeStrokeColor"
            :pannable="true"
            :zoomable="true"
            :width="164"
            :height="104"
            mask-color="var(--color-provenance-mask)"
            mask-stroke-color="var(--color-active)"
            aria-label="溯源图缩略导航"
            position="bottom-right"
          />
          <template #node-provenance="{ data }">
            <div
              class="prov-node"
              :class="[
                `prov-node--${data.kind}`,
                `prov-node--phase-${data.phase}`,
                { 'prov-node--selected': data.nodeId === selectedNodeId },
              ]"
              :aria-label="`${kindLabel(data.kind)}：${nodeLabel(data.label, data.kind)}`"
              :aria-pressed="data.nodeId === selectedNodeId"
              role="button"
              tabindex="0"
              :title="nodeTooltip(data)"
              @keydown.enter.stop.prevent="emit('select-node', data.nodeId)"
              @keydown.space.stop.prevent="emit('select-node', data.nodeId)"
            >
              <Handle
                type="target"
                :position="isCompact ? Position.Top : Position.Left"
                :connectable="false"
              />
              <header>
                <span class="prov-node__icon" aria-hidden="true">
                  <component :is="nodeIcon(data.kind)" :size="15" stroke-width="1.8" />
                </span>
                <span class="prov-node__kind">{{ kindLabel(data.kind) }}</span>
                <span class="prov-node__phase">{{ phaseShortLabel(data.phase) }}</span>
              </header>
              <strong class="prov-node__label">{{ nodeLabel(data.label, data.kind) }}</strong>
              <span v-if="nodeSummary(data.metadata)" class="prov-node__summary">
                {{ nodeSummary(data.metadata) }}
              </span>
              <span v-if="nodeMetaBadge(data.metadata)" class="prov-node__badge">
                {{ nodeMetaBadge(data.metadata) }}
              </span>
              <Handle
                type="source"
                :position="isCompact ? Position.Bottom : Position.Right"
                :connectable="false"
              />
            </div>
          </template>
        </VueFlow>

        <div v-if="isLayouting" class="provenance-layout-status" role="status">
          <LoaderCircle :size="17" aria-hidden="true" />
          正在整理证据关系…
        </div>

        <div v-if="!visibleNodes.length" class="provenance-filter-empty">
          <p>当前筛选没有可见节点</p>
          <button type="button" @click="resetFilters">恢复全部节点</button>
        </div>

        <span v-if="hiddenNodeCount" class="provenance-hidden-count" role="status">
          已收拢 {{ hiddenNodeCount }} 个旁支或阶段节点
        </span>
      </div>

      <p class="sr-only" aria-live="polite">
        当前显示 {{ visibleNodes.length }} 个节点、{{ visibleEdges.length }} 条关系；已选择
        {{ selectedNodeId ? "一个节点并显示相关路径" : "无节点" }}。
      </p>
    </template>
    <p v-else class="provenance-empty">该证据链暂无溯源节点</p>
  </div>
</template>

<script setup lang="ts">
import {
  Activity,
  BrainCircuit,
  ClipboardList,
  FileKey,
  FileSearch,
  Filter,
  Fingerprint,
  Gavel,
  Layers3,
  LoaderCircle,
  MailWarning,
  Maximize2,
  Minimize2,
  Route,
  RotateCcw,
  Scan,
  ScrollText,
  Search,
  ShieldCheck,
  UserCheck,
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
  type GraphNode,
  type Node,
  type ViewportTransform,
  useVueFlow,
} from "@vue-flow/core";
import { MiniMap } from "@vue-flow/minimap";
import ELK, { type ElkNode } from "elkjs/lib/elk-api.js";
import ElkWorker from "elkjs/lib/elk-worker.min.js?worker";
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch, type Component } from "vue";

import type {
  EvidenceStageId,
  ProvenanceEdge,
  ProvenanceGraph,
  ProvenanceNode,
} from "../../types/dashboard";
import { getDecisionLabel, getEventTypeLabel } from "../../utils/dashboard-formatters";
import { getProvenanceRelationLabel, getProvenanceRiskScore } from "../../utils/provenance";
import { formatRuleIdsInTextForDisplay } from "../../utils/rule-display";

defineOptions({ name: "ProvenanceGraph" });

const props = defineProps<{
  graph: ProvenanceGraph;
  selectedNodeId?: string;
}>();

const emit = defineEmits<{
  "select-node": [nodeId: string];
}>();

interface ProvenanceNodeData extends ProvenanceNode {
  phase: EvidenceStageId;
}

interface PositionedNode {
  id: string;
  x: number;
  y: number;
}

interface ViewportSnapshot {
  anchorId: string | null;
  anchorScreenX: number | null;
  anchorScreenY: number | null;
  viewport: ViewportTransform;
}

const LARGE_GRAPH_THRESHOLD = 24;
const LAYOUT_CACHE_MAX_ENTRIES = 24;
const NODE_WIDTH = 220;
const NODE_HEIGHT = 108;
const layoutCache = new Map<string, PositionedNode[]>();
const elk = new ELK({
  algorithms: ["layered"],
  workerFactory: () => new ElkWorker(),
});
const flowId = `provenance-${props.graph.traceId}`;
const { fitView, setCenter, setViewport, updateNode, zoomTo } = useVueFlow(flowId);
const flowNodes = ref<Node<ProvenanceNodeData>[]>([]);
const isCompact = ref(false);
const isFullscreen = ref(false);
const isLayouting = ref(false);
const prefersReducedMotion = ref(false);
const viewportZoom = ref(1);
const searchQuery = ref("");
const searchResultIndex = ref(0);
const activeKind = ref("all");
const collapsedPhases = ref<ReadonlySet<EvidenceStageId>>(new Set());
const viewMode = ref<"all" | "critical">(
  props.graph.nodes.length > LARGE_GRAPH_THRESHOLD ||
    props.graph.nodes.some((node) => node.metadata.critical === false)
    ? "critical"
    : "all",
);
const hoveredEdgeId = ref<string | null>(null);
let layoutGeneration = 0;
let positionByNodeId = new Map<string, PositionedNode>();
let compactMedia: MediaQueryList | null = null;
let motionMedia: MediaQueryList | null = null;
let pendingViewportSnapshot: ViewportSnapshot | null = null;
let latestViewport: ViewportTransform | null = null;

const phaseDefinitions = [
  { id: "input_trust", index: "01", short: "输入", title: "输入与信任" },
  { id: "context_intent", index: "02", short: "意图", title: "上下文与模型意图" },
  { id: "tool_policy", index: "03", short: "策略", title: "工具、资源与策略" },
  { id: "outcome_audit", index: "04", short: "结果", title: "执行结果与审计" },
] as const;

const kindDefinitions: Record<string, { icon: Component; label: string; miniMapColor: string }> = {
  action: { icon: Wrench, label: "受控动作", miniMapColor: "var(--color-chart-warning)" },
  action_critic: {
    icon: FileSearch,
    label: "复核",
    miniMapColor: "var(--color-node-action-critic)",
  },
  approval: { icon: UserCheck, label: "人工审批", miniMapColor: "var(--color-chart-warning)" },
  audit: { icon: Fingerprint, label: "审计记录", miniMapColor: "var(--color-node-audit)" },
  config_audit: {
    icon: FileSearch,
    label: "配置审计",
    miniMapColor: "var(--color-node-config-audit)",
  },
  context: { icon: Layers3, label: "上下文", miniMapColor: "var(--color-chart-secondary)" },
  decision: {
    icon: Gavel,
    label: "安全决定",
    miniMapColor: "var(--color-node-decision)",
  },
  event: { icon: Activity, label: "运行时事件", miniMapColor: "var(--color-node-event)" },
  model_intent: {
    icon: BrainCircuit,
    label: "模型意图",
    miniMapColor: "var(--color-chart-secondary)",
  },
  policy: { icon: ShieldCheck, label: "当时生效的策略", miniMapColor: "var(--color-node-event)" },
  resource: { icon: FileKey, label: "资源目标", miniMapColor: "var(--color-chart-warning)" },
  review: {
    icon: FileSearch,
    label: "风险组合",
    miniMapColor: "var(--color-node-action-critic)",
  },
  rule: { icon: ShieldCheck, label: "命中规则", miniMapColor: "var(--color-node-decision)" },
  runtime_result: {
    icon: Activity,
    label: "运行时结果",
    miniMapColor: "var(--color-node-event)",
  },
  source: { icon: MailWarning, label: "来源", miniMapColor: "var(--color-chart-slate)" },
  task: { icon: ClipboardList, label: "原始任务", miniMapColor: "var(--color-chart-slate)" },
};

function metadataString(metadata: Record<string, unknown>, key: string): string {
  const value = metadata[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function metadataBoolean(metadata: Record<string, unknown>, key: string): boolean {
  return metadata[key] === true;
}

function displayText(value: string): string {
  return formatRuleIdsInTextForDisplay(value);
}

function kindLabel(kind: string): string {
  return kindDefinitions[kind]?.label ?? kind;
}

function nodeIcon(kind: string): Component {
  return kindDefinitions[kind]?.icon ?? ScrollText;
}

function nodeLabel(value: string, kind: string): string {
  if (kind === "decision" && ["allow", "ask", "deny", "unknown"].includes(value)) {
    return getDecisionLabel(value as "allow" | "ask" | "deny" | "unknown");
  }
  if (kind === "event" || kind === "audit" || kind === "config_audit") {
    return getEventTypeLabel(value);
  }
  return displayText(value);
}

function nodePhase(node: ProvenanceNode): EvidenceStageId {
  const explicit = metadataString(node.metadata, "phase");
  if (
    explicit === "input_trust" ||
    explicit === "context_intent" ||
    explicit === "tool_policy" ||
    explicit === "outcome_audit"
  ) {
    return explicit;
  }
  if (node.kind === "task" || node.kind === "source") return "input_trust";
  if (node.kind === "context" || node.kind === "model_intent") return "context_intent";
  if (
    node.kind === "approval" ||
    node.kind === "runtime_result" ||
    node.kind === "audit" ||
    node.kind === "action_critic"
  ) {
    return "outcome_audit";
  }
  return "tool_policy";
}

function phaseShortLabel(phase: EvidenceStageId): string {
  return phaseDefinitions.find((item) => item.id === phase)?.short ?? "";
}

function nodeSummary(metadata: Record<string, unknown>): string {
  return displayText(metadataString(metadata, "summary"));
}

function nodeMetaBadge(metadata: Record<string, unknown>): string {
  const riskScore = getProvenanceRiskScore(metadata);
  if (riskScore !== "") return `风险 ${riskScore}`;
  const decision = metadataString(metadata, "decision");
  if (decision === "allow" || decision === "ask" || decision === "deny") {
    return getDecisionLabel(decision);
  }
  const status = metadataString(metadata, "status");
  const labels: Record<string, string> = {
    allowed: "单次放行",
    denied: "审批拒绝",
    executed: "已执行",
    failed: "执行失败",
    not_invoked: "未调用",
    pending: "待审批",
  };
  return labels[status] ?? status;
}

function nodeTooltip(data: ProvenanceNodeData): string {
  return [
    kindLabel(data.kind),
    nodeLabel(data.label, data.kind),
    nodeSummary(data.metadata),
    nodeMetaBadge(data.metadata),
  ]
    .filter(Boolean)
    .join(" · ");
}

const phaseOptions = computed(() =>
  phaseDefinitions.map((phase) => ({
    ...phase,
    count: props.graph.nodes.filter((node) => nodePhase(node) === phase.id).length,
  })),
);

const kindOptions = computed(() => {
  const counts = new Map<string, number>();
  props.graph.nodes.forEach((node) => {
    counts.set(node.kind, (counts.get(node.kind) ?? 0) + 1);
  });
  return [...counts.entries()]
    .map(([value, count]) => ({ count, label: kindLabel(value), value }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
});

const nodeById = computed(
  () => new Map(props.graph.nodes.map((node) => [node.nodeId, node] as const)),
);

const graphAdjacency = computed(() => {
  const incoming = new Map<string, string[]>();
  const outgoing = new Map<string, string[]>();
  props.graph.edges.forEach((edge) => {
    const incomingNodes = incoming.get(edge.targetNodeId);
    if (incomingNodes) incomingNodes.push(edge.sourceNodeId);
    else incoming.set(edge.targetNodeId, [edge.sourceNodeId]);
    const outgoingNodes = outgoing.get(edge.sourceNodeId);
    if (outgoingNodes) outgoingNodes.push(edge.targetNodeId);
    else outgoing.set(edge.sourceNodeId, [edge.targetNodeId]);
  });
  return { incoming, outgoing };
});

function buildReachableNodeIds(startNodeId: string | undefined): ReadonlySet<string> | null {
  if (!startNodeId || !nodeById.value.has(startNodeId)) return null;
  const reachable = new Set([startNodeId]);
  const walk = (lookup: Map<string, string[]>) => {
    const visited = new Set([startNodeId]);
    const queue = [startNodeId];
    for (let index = 0; index < queue.length; index += 1) {
      const current = queue[index]!;
      for (const next of lookup.get(current) ?? []) {
        if (visited.has(next)) continue;
        visited.add(next);
        reachable.add(next);
        queue.push(next);
      }
    }
  };
  walk(graphAdjacency.value.incoming);
  walk(graphAdjacency.value.outgoing);
  return reachable;
}

const contextNodeIds = computed(() => buildReachableNodeIds(props.selectedNodeId));

const criticalNodeIds = computed<ReadonlySet<string>>(() => {
  const explicit = new Set(
    props.graph.nodes
      .filter((node) => metadataBoolean(node.metadata, "critical"))
      .map((node) => node.nodeId),
  );
  if (explicit.size) return explicit;
  const decision =
    props.graph.nodes.find((node) => node.kind === "decision") ?? props.graph.nodes[0];
  return (
    buildReachableNodeIds(decision?.nodeId) ??
    new Set(props.graph.nodes.slice(0, 24).map((n) => n.nodeId))
  );
});

const baseVisibleNodes = computed(() =>
  props.graph.nodes.filter((node) => {
    if (collapsedPhases.value.has(nodePhase(node))) return false;
    if (activeKind.value !== "all" && node.kind !== activeKind.value) return false;
    if (viewMode.value === "critical") {
      return (
        criticalNodeIds.value.has(node.nodeId) || contextNodeIds.value?.has(node.nodeId) === true
      );
    }
    return true;
  }),
);

const visibleNodes = computed(() => baseVisibleNodes.value);
const visibleNodeIds = computed(() => new Set(visibleNodes.value.map((node) => node.nodeId)));
const visibleEdges = computed(() =>
  props.graph.edges.filter(
    (edge) =>
      visibleNodeIds.value.has(edge.sourceNodeId) && visibleNodeIds.value.has(edge.targetNodeId),
  ),
);
const renderedNodeIds = computed<ReadonlySet<string>>(
  () => new Set((flowNodes.value as unknown as Array<{ id: string }>).map((node) => node.id)),
);
const hiddenNodeCount = computed(() => props.graph.nodes.length - visibleNodes.value.length);
const hasCollapsibleBranches = computed(
  () =>
    props.graph.nodes.length > LARGE_GRAPH_THRESHOLD ||
    props.graph.nodes.some((node) => node.metadata.critical === false),
);

const searchMatches = computed(() => {
  const query = searchQuery.value.toLocaleLowerCase("zh-CN");
  if (!query) return [];
  return props.graph.nodes.filter((node) =>
    [
      node.label,
      node.kind,
      kindLabel(node.kind),
      metadataString(node.metadata, "summary"),
      metadataString(node.metadata, "status"),
      metadataString(node.metadata, "phase"),
    ]
      .join(" ")
      .toLocaleLowerCase("zh-CN")
      .includes(query),
  );
});

const zoomBand = computed(() =>
  viewportZoom.value < 0.62 ? "overview" : viewportZoom.value < 0.95 ? "standard" : "detail",
);

function layoutKey(): string {
  return JSON.stringify({
    direction: isCompact.value ? "DOWN" : "RIGHT",
    edges: visibleEdges.value.map((edge) => [edge.sourceNodeId, edge.targetNodeId, edge.relation]),
    nodes: visibleNodes.value.map((node) => node.nodeId),
  });
}

function getCachedLayout(key: string): PositionedNode[] | undefined {
  const cached = layoutCache.get(key);
  if (!cached) return undefined;
  layoutCache.delete(key);
  layoutCache.set(key, cached);
  return cached;
}

function cacheLayout(key: string, positioned: PositionedNode[]): void {
  layoutCache.delete(key);
  layoutCache.set(key, positioned);
  while (layoutCache.size > LAYOUT_CACHE_MAX_ENTRIES) {
    const oldestKey = layoutCache.keys().next().value;
    if (oldestKey === undefined) break;
    layoutCache.delete(oldestKey);
  }
}

function fallbackLayout(nodes: readonly ProvenanceNode[]): PositionedNode[] {
  const phaseIndexes = new Map(phaseDefinitions.map((phase, index) => [phase.id, index]));
  const phaseCounts = new Map<EvidenceStageId, number>();
  return nodes.map((node) => {
    const phase = nodePhase(node);
    const phaseIndex = phaseIndexes.get(phase) ?? 0;
    const branchIndex = phaseCounts.get(phase) ?? 0;
    phaseCounts.set(phase, branchIndex + 1);
    return isCompact.value
      ? {
          id: node.nodeId,
          x: 150 + branchIndex * (NODE_WIDTH + 46),
          y: 80 + phaseIndex * (NODE_HEIGHT + 150),
        }
      : {
          id: node.nodeId,
          x: 80 + phaseIndex * (NODE_WIDTH + 170),
          y: 90 + branchIndex * (NODE_HEIGHT + 46),
        };
  });
}

function collectElkPositions(
  nodes: readonly ElkNode[],
  offsetX = 0,
  offsetY = 0,
): PositionedNode[] {
  return nodes.flatMap((node) => {
    const x = offsetX + (node.x ?? 0);
    const y = offsetY + (node.y ?? 0);
    return node.children?.length
      ? collectElkPositions(node.children, x, y)
      : [{ id: node.id, x, y }];
  });
}

async function runLayout(): Promise<void> {
  const generation = ++layoutGeneration;
  if (!visibleNodes.value.length) {
    flowNodes.value = [];
    isLayouting.value = false;
    pendingViewportSnapshot = null;
    return;
  }
  const key = layoutKey();
  const cached = getCachedLayout(key);
  isLayouting.value = !cached;
  let positioned = cached;
  if (!positioned) {
    const direction = isCompact.value ? "DOWN" : "RIGHT";
    const innerDirection = isCompact.value ? "RIGHT" : "DOWN";
    const phaseGroups = phaseDefinitions
      .map((phase) => {
        const nodes = visibleNodes.value.filter((node) => nodePhase(node) === phase.id);
        const nodeIds = new Set(nodes.map((node) => node.nodeId));
        return {
          children: nodes.map((node) => ({
            height: NODE_HEIGHT,
            id: node.nodeId,
            width: NODE_WIDTH,
          })),
          edges: visibleEdges.value
            .filter((edge) => nodeIds.has(edge.sourceNodeId) && nodeIds.has(edge.targetNodeId))
            .map((edge) => ({
              id: `layout:${edge.edgeId}`,
              sources: [edge.sourceNodeId],
              targets: [edge.targetNodeId],
            })),
          id: `phase:${phase.id}`,
          layoutOptions: {
            "elk.algorithm": "layered",
            "elk.direction": innerDirection,
            "elk.edgeRouting": "ORTHOGONAL",
            "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
            "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
            "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
            "elk.layered.spacing.nodeNodeBetweenLayers": "44",
            "elk.padding": "[top=24,left=20,bottom=24,right=20]",
            "elk.spacing.edgeNode": "26",
            "elk.spacing.nodeNode": "30",
          },
        } satisfies ElkNode;
      })
      .filter((group) => group.children.length);
    const graph: ElkNode = {
      children: phaseGroups,
      edges: phaseGroups.slice(0, -1).map((group, index) => ({
        id: `layout:phase:${index}`,
        sources: [group.id],
        targets: [phaseGroups[index + 1]!.id],
      })),
      id: "root",
      layoutOptions: {
        "elk.algorithm": "layered",
        "elk.direction": direction,
        "elk.edgeRouting": "ORTHOGONAL",
        "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
        "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
        "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
        "elk.layered.spacing.nodeNodeBetweenLayers": "64",
        "elk.padding": "[top=32,left=32,bottom=32,right=32]",
        "elk.spacing.edgeNode": "42",
        "elk.spacing.nodeNode": "60",
      },
    };
    try {
      const result = await elk.layout(graph);
      positioned = collectElkPositions(result.children ?? []);
      cacheLayout(key, positioned);
    } catch {
      positioned = fallbackLayout(visibleNodes.value);
    }
  }
  if (generation !== layoutGeneration) return;
  const positions = new Map(positioned.map((node) => [node.id, node]));
  positionByNodeId = positions;
  const nextNodes: Node<ProvenanceNodeData>[] = [];
  for (const node of visibleNodes.value) {
    const position = positions.get(node.nodeId) ?? { x: 0, y: 0 };
    const isInContext = !contextNodeIds.value || contextNodeIds.value.has(node.nodeId);
    nextNodes.push({
      ariaLabel: `${kindLabel(node.kind)}：${nodeLabel(node.label, node.kind)}`,
      class: isInContext ? "prov-flow-node--context" : "prov-flow-node--dimmed",
      data: { ...node, phase: nodePhase(node) },
      focusable: true,
      height: NODE_HEIGHT,
      id: node.nodeId,
      position: { x: position.x, y: position.y },
      selectable: true,
      sourcePosition: isCompact.value ? Position.Bottom : Position.Right,
      targetPosition: isCompact.value ? Position.Top : Position.Left,
      type: "provenance",
      width: NODE_WIDTH,
    });
  }
  flowNodes.value = nextNodes;
  await nextTick();
  await new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()));
  });
  if (generation !== layoutGeneration) return;
  const viewportSnapshot = pendingViewportSnapshot;
  pendingViewportSnapshot = null;
  if (viewportSnapshot) {
    await restoreViewport(viewportSnapshot);
    isLayouting.value = false;
    return;
  }
  await positionInitialCanvas();
  isLayouting.value = false;
}

function relationType(edge: ProvenanceEdge): string {
  return metadataString(edge.metadata, "relation_type") || "causal";
}

function edgeStroke(type: string): string {
  if (type === "detection") return "var(--color-danger)";
  if (type === "approval") return "var(--color-warning)";
  if (type === "audit") return "var(--color-chart-slate)";
  if (type === "execution") return "var(--color-active)";
  if (type === "policy") return "var(--color-active-strong)";
  return "var(--color-border-strong)";
}

function edgeDash(type: string): string | undefined {
  if (type === "detection") return "6 4";
  if (type === "approval") return "2 4";
  if (type === "audit") return "9 4";
  return undefined;
}

const flowEdges = computed<Edge[]>(() =>
  visibleEdges.value
    .filter(
      (edge) =>
        renderedNodeIds.value.has(edge.sourceNodeId) &&
        renderedNodeIds.value.has(edge.targetNodeId),
    )
    .map((edge) => {
      const type = relationType(edge);
      const isInContext =
        !contextNodeIds.value ||
        (contextNodeIds.value.has(edge.sourceNodeId) &&
          contextNodeIds.value.has(edge.targetNodeId));
      const isFocused =
        hoveredEdgeId.value === edge.edgeId || Boolean(props.selectedNodeId && isInContext);
      const isAdjacentToSelection =
        props.selectedNodeId === edge.sourceNodeId || props.selectedNodeId === edge.targetNodeId;
      const showLabel =
        hoveredEdgeId.value === edge.edgeId ||
        isAdjacentToSelection ||
        (viewportZoom.value >= 1.15 && !props.selectedNodeId);
      const stroke = edgeStroke(type);
      const sourceNode = nodeById.value.get(edge.sourceNodeId);
      const targetNode = nodeById.value.get(edge.targetNodeId);
      return {
        ariaLabel: `${kindLabel(sourceNode?.kind ?? "节点")} ${
          getProvenanceRelationLabel(edge.relation) || edge.relation
        } ${kindLabel(targetNode?.kind ?? "节点")}`,
        class: [`prov-edge--${type}`, { "prov-edge--dimmed": !isInContext }],
        data: { relationType: type },
        id: edge.edgeId,
        interactionWidth: 18,
        label: showLabel ? getProvenanceRelationLabel(edge.relation) || edge.relation : "",
        labelBgBorderRadius: 4,
        labelBgPadding: [3, 5],
        labelBgStyle: {
          fill: "var(--color-surface)",
          fillOpacity: isInContext ? 0.96 : 0.35,
        },
        labelStyle: {
          fill: "var(--color-text-muted)",
          fontSize: "11px",
          fontWeight: 620,
          opacity: isInContext ? 1 : 0.28,
        },
        markerEnd: {
          color: stroke,
          height: 16,
          type: MarkerType.ArrowClosed,
          width: 16,
        },
        selectable: false,
        source: edge.sourceNodeId,
        sourceHandle: undefined,
        style: {
          opacity: isInContext ? 0.95 : 0.18,
          stroke,
          strokeDasharray: edgeDash(type),
          strokeWidth: isFocused ? 2.4 : type === "execution" ? 2 : 1.5,
        },
        target: edge.targetNodeId,
        targetHandle: undefined,
        type: "smoothstep",
      };
    }),
);

function handleNodeClick(event: { node: { id: string } }) {
  emit("select-node", event.node.id);
}

function handleEdgeMouseEnter(event: { edge: { id: string } }) {
  hoveredEdgeId.value = event.edge.id;
}

function handleEdgeMouseLeave() {
  hoveredEdgeId.value = null;
}

function handleViewportChange(viewport: ViewportTransform) {
  latestViewport = { ...viewport };
  viewportZoom.value = viewport.zoom;
}

function miniMapNodeColor(node: GraphNode): string {
  const kind = (node.data as ProvenanceNodeData | undefined)?.kind ?? "";
  return kindDefinitions[kind]?.miniMapColor ?? "var(--color-node-audit)";
}

function miniMapNodeStrokeColor(node: GraphNode): string {
  return node.id === props.selectedNodeId ? "var(--color-focus)" : "var(--color-surface)";
}

function togglePhase(phase: EvidenceStageId) {
  const next = new Set(collapsedPhases.value);
  if (next.has(phase)) next.delete(phase);
  else next.add(phase);
  collapsedPhases.value = next;
}

function toggleViewMode() {
  viewMode.value = viewMode.value === "critical" ? "all" : "critical";
}

function resetFilters() {
  collapsedPhases.value = new Set();
  activeKind.value = "all";
  viewMode.value = "all";
}

async function fitCanvas() {
  if (!flowNodes.value.length) return;
  await fitView({
    duration: prefersReducedMotion.value ? 0 : 180,
    maxZoom: 1.05,
    minZoom: 0.28,
    padding: "9%",
  });
}

async function resetZoom() {
  await zoomTo(1, { duration: prefersReducedMotion.value ? 0 : 160 });
}

async function focusNode(nodeId: string) {
  const position = positionByNodeId.get(nodeId);
  if (!position) return;
  await setCenter(position.x + NODE_WIDTH / 2, position.y + NODE_HEIGHT / 2, {
    duration: prefersReducedMotion.value ? 0 : 180,
    zoom: Math.max(1, viewportZoom.value),
  });
}

async function positionInitialCanvas() {
  if (props.selectedNodeId && visibleNodeIds.value.has(props.selectedNodeId)) {
    await focusNode(props.selectedNodeId);
    return;
  }
  const decisionNode = visibleNodes.value.find((node) => node.kind === "decision");
  const resultNode = visibleNodes.value.find((node) => node.kind === "runtime_result");
  const decisionPosition = decisionNode ? positionByNodeId.get(decisionNode.nodeId) : undefined;
  const resultPosition = resultNode ? positionByNodeId.get(resultNode.nodeId) : undefined;
  if (flowNodes.value.length > 18 && decisionPosition && resultPosition) {
    await setCenter(
      (decisionPosition.x + resultPosition.x) / 2 + NODE_WIDTH / 2,
      (decisionPosition.y + resultPosition.y) / 2 + NODE_HEIGHT / 2,
      {
        duration: prefersReducedMotion.value ? 0 : 180,
        zoom: isCompact.value ? 0.68 : 0.58,
      },
    );
    return;
  }
  await fitCanvas();
}

function captureViewportSnapshot(): ViewportSnapshot | null {
  const viewport = latestViewport;
  if (!viewport) return null;
  const canvas = document.getElementById(flowId);
  const graphCenter = canvas
    ? {
        x: (canvas.clientWidth / 2 - viewport.x) / viewport.zoom,
        y: (canvas.clientHeight / 2 - viewport.y) / viewport.zoom,
      }
    : null;
  const selectedPosition = props.selectedNodeId
    ? positionByNodeId.get(props.selectedNodeId)
    : undefined;
  const anchor =
    selectedPosition ??
    (graphCenter
      ? [...positionByNodeId.values()].sort((left, right) => {
          const leftDistance =
            (left.x + NODE_WIDTH / 2 - graphCenter.x) ** 2 +
            (left.y + NODE_HEIGHT / 2 - graphCenter.y) ** 2;
          const rightDistance =
            (right.x + NODE_WIDTH / 2 - graphCenter.x) ** 2 +
            (right.y + NODE_HEIGHT / 2 - graphCenter.y) ** 2;
          return leftDistance - rightDistance || left.id.localeCompare(right.id);
        })[0]
      : undefined);
  return {
    anchorId: anchor?.id ?? null,
    anchorScreenX: anchor ? (anchor.x + NODE_WIDTH / 2) * viewport.zoom + viewport.x : null,
    anchorScreenY: anchor ? (anchor.y + NODE_HEIGHT / 2) * viewport.zoom + viewport.y : null,
    viewport,
  };
}

async function restoreViewport(snapshot: ViewportSnapshot): Promise<void> {
  const anchor = snapshot.anchorId ? positionByNodeId.get(snapshot.anchorId) : undefined;
  if (anchor && snapshot.anchorScreenX !== null && snapshot.anchorScreenY !== null) {
    await setViewport(
      {
        x: snapshot.anchorScreenX - (anchor.x + NODE_WIDTH / 2) * snapshot.viewport.zoom,
        y: snapshot.anchorScreenY - (anchor.y + NODE_HEIGHT / 2) * snapshot.viewport.zoom,
        zoom: snapshot.viewport.zoom,
      },
      { duration: 0 },
    );
    return;
  }
  await setViewport(snapshot.viewport, { duration: 0 });
}

function updateNodeContextClasses() {
  const context = contextNodeIds.value;
  (flowNodes.value as unknown as Array<{ id: string }>).forEach((node) => {
    updateNode(node.id, {
      class:
        !context || context.has(node.id) ? "prov-flow-node--context" : "prov-flow-node--dimmed",
    });
  });
}

function syncFlowNodeData() {
  const latestNodes = nodeById.value;
  (flowNodes.value as unknown as Array<{ id: string }>).forEach((flowNode) => {
    const node = latestNodes.get(flowNode.id);
    if (!node) return;
    updateNode(flowNode.id, {
      ariaLabel: `${kindLabel(node.kind)}：${nodeLabel(node.label, node.kind)}`,
      data: { ...node, phase: nodePhase(node) },
    });
  });
}

async function focusSearchResult() {
  if (!searchMatches.value.length) return;
  const match = searchMatches.value[searchResultIndex.value % searchMatches.value.length]!;
  searchResultIndex.value += 1;
  activeKind.value = "all";
  const phase = nodePhase(match);
  if (collapsedPhases.value.has(phase)) {
    const next = new Set(collapsedPhases.value);
    next.delete(phase);
    collapsedPhases.value = next;
  }
  if (viewMode.value === "critical" && !criticalNodeIds.value.has(match.nodeId)) {
    viewMode.value = "all";
  }
  emit("select-node", match.nodeId);
  await nextTick();
  await focusNode(match.nodeId);
}

async function toggleFullscreen() {
  isFullscreen.value = !isFullscreen.value;
  await nextTick();
  await fitCanvas();
}

function handleEscape(event: KeyboardEvent) {
  if (event.key === "Escape" && isFullscreen.value) {
    isFullscreen.value = false;
    void nextTick().then(fitCanvas);
  }
}

function updateMediaState() {
  isCompact.value = compactMedia?.matches ?? false;
  prefersReducedMotion.value = motionMedia?.matches ?? false;
}

watch(
  () => props.graph.traceId,
  (traceId, previousTraceId) => {
    if (!previousTraceId || traceId === previousTraceId) return;
    viewMode.value =
      props.graph.nodes.length > LARGE_GRAPH_THRESHOLD ||
      props.graph.nodes.some((node) => node.metadata.critical === false)
        ? "critical"
        : "all";
    collapsedPhases.value = new Set();
    activeKind.value = "all";
    pendingViewportSnapshot = null;
  },
);

watch(
  () =>
    `${props.graph.nodes.map((node) => node.nodeId).join("|")}\u0000${props.graph.edges
      .map((edge) => edge.edgeId)
      .join("|")}`,
  (graphKey, previousGraphKey) => {
    if (!previousGraphKey || graphKey === previousGraphKey) return;
    pendingViewportSnapshot = captureViewportSnapshot();
    if (
      activeKind.value !== "all" &&
      !props.graph.nodes.some((node) => node.kind === activeKind.value)
    ) {
      activeKind.value = "all";
    }
  },
);

watch(
  () => props.graph.nodes,
  () => syncFlowNodeData(),
);

watch(
  [
    () => visibleNodes.value.map((node) => node.nodeId).join("|"),
    () => visibleEdges.value.map((edge) => edge.edgeId).join("|"),
    isCompact,
  ],
  () => {
    void runLayout();
  },
  { immediate: true },
);

watch(
  () => props.selectedNodeId,
  async (nodeId) => {
    updateNodeContextClasses();
    if (!nodeId) return;
    await nextTick();
    await focusNode(nodeId);
  },
);

watch(searchQuery, () => {
  searchResultIndex.value = 0;
});

onMounted(() => {
  compactMedia = window.matchMedia("(max-width: 68rem)");
  motionMedia = window.matchMedia("(prefers-reduced-motion: reduce)");
  updateMediaState();
  compactMedia.addEventListener("change", updateMediaState);
  motionMedia.addEventListener("change", updateMediaState);
  window.addEventListener("keydown", handleEscape);
});

onBeforeUnmount(() => {
  compactMedia?.removeEventListener("change", updateMediaState);
  motionMedia?.removeEventListener("change", updateMediaState);
  window.removeEventListener("keydown", handleEscape);
  elk.terminateWorker();
});
</script>

<style>
@import "@vue-flow/core/dist/style.css";
@import "@vue-flow/core/dist/theme-default.css";
@import "@vue-flow/controls/dist/style.css";
@import "@vue-flow/minimap/dist/style.css";
</style>

<style scoped lang="scss">
.provenance-workbench {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  grid-template-rows: auto auto minmax(34rem, 66vh);
  min-height: 0;
  overflow: hidden;
  position: relative;
}

.provenance-workbench--fullscreen {
  border-radius: 0;
  grid-template-rows: auto auto minmax(0, 1fr);
  inset: 0;
  position: fixed;
  z-index: 100;
}

.provenance-toolbar {
  align-items: center;
  background: var(--color-surface);
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(15rem, 1fr) auto auto;
  padding: var(--space-3);
}

.provenance-toolbar__search {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  max-width: 28rem;
  min-height: 2.25rem;
  padding-left: var(--space-3);
}

.provenance-toolbar__search input {
  background: transparent;
  border: 0;
  color: var(--color-text);
  font: inherit;
  min-width: 0;
  outline: 0;
  padding: 0 var(--space-2);
}

.provenance-toolbar__search button,
.provenance-toolbar__actions button {
  align-items: center;
  background: transparent;
  border: 0;
  border-left: 1px solid var(--color-border);
  color: var(--color-link);
  cursor: pointer;
  display: inline-flex;
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-1);
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}

.provenance-toolbar__search button:disabled {
  color: var(--color-text-subtle);
  cursor: not-allowed;
}

.provenance-toolbar__select {
  align-items: center;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: flex;
  gap: var(--space-1);
  min-height: 2.25rem;
  padding-left: var(--space-2);
}

.provenance-toolbar__select select {
  background: transparent;
  border: 0;
  color: var(--color-text);
  font: inherit;
  font-size: var(--font-size-11);
  min-height: 2.25rem;
  outline: 0;
  padding-right: var(--space-2);
}

.provenance-toolbar__actions {
  align-items: center;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: flex;
}

.provenance-toolbar__actions button:first-child {
  border-left: 0;
}

.provenance-toolbar button:focus-visible,
.provenance-toolbar select:focus-visible,
.provenance-toolbar__search:focus-within {
  box-shadow: var(--shadow-focus);
  outline: 2px solid var(--color-focus);
  outline-offset: 1px;
}

.provenance-phases {
  background: var(--color-surface-muted);
  border-bottom: 1px solid var(--color-border);
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.provenance-phases button {
  align-items: center;
  background: transparent;
  border: 0;
  border-left: 1px solid var(--color-border);
  color: var(--color-text);
  cursor: pointer;
  display: grid;
  gap: var(--space-2);
  grid-template-columns: auto minmax(0, 1fr) auto;
  min-height: 2.7rem;
  padding: var(--space-2) var(--space-3);
  text-align: left;
}

.provenance-phases button:first-child {
  border-left: 0;
}

.provenance-phases button > span {
  color: var(--color-active);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.provenance-phases button > strong {
  font-size: var(--font-size-11);
}

.provenance-phases button > b {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-pill);
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  min-width: 1.5rem;
  padding: 0.1rem var(--space-1);
  text-align: center;
}

.provenance-phases__item--collapsed {
  opacity: 0.48;
}

.provenance-phases button:focus-visible {
  box-shadow: inset 0 0 0 2px var(--color-focus);
  outline: 0;
}

.provenance-canvas {
  min-height: 0;
  overflow: hidden;
  position: relative;
}

.provenance-flow {
  background: var(--gradient-provenance-lanes-horizontal), var(--color-surface-muted);
  height: 100%;
  width: 100%;
}

.provenance-workbench--compact .provenance-flow {
  background: var(--gradient-provenance-lanes-vertical), var(--color-surface-muted);
}

.provenance-flow :deep(.vue-flow__node) {
  transition: opacity var(--transition-fast);
}

.provenance-flow :deep(.vue-flow__node.prov-flow-node--dimmed) {
  opacity: 0.18;
}

.provenance-flow :deep(.vue-flow__edge-path),
.provenance-flow :deep(.vue-flow__edge-text) {
  transition:
    opacity var(--transition-fast),
    stroke-width var(--transition-fast);
}

.provenance-flow :deep(.vue-flow__edge.prov-edge--dimmed) {
  pointer-events: none;
}

.provenance-flow :deep(.vue-flow__controls),
.provenance-flow :deep(.vue-flow__minimap) {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  box-shadow: var(--shadow-subtle);
  overflow: hidden;
}

.provenance-flow :deep(.vue-flow__controls-button) {
  background: var(--color-surface);
  border-bottom-color: var(--color-border);
  color: var(--color-text);
}

.prov-node {
  --node-accent: var(--color-chart-slate);
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-left: 4px solid var(--node-accent);
  border-radius: var(--radius-2);
  box-sizing: border-box;
  cursor: pointer;
  display: grid;
  gap: 0.32rem;
  height: 6.75rem;
  padding: var(--space-3);
  width: 13.75rem;
}

.prov-node:hover {
  border-color: var(--node-accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--node-accent) 14%, transparent);
}

.prov-node:focus-visible {
  box-shadow: var(--shadow-focus);
  outline: 2px solid var(--color-focus);
  outline-offset: 2px;
}

.prov-node--selected {
  border-color: var(--color-focus);
  box-shadow: var(--glow-focus-soft);
}

.prov-node--task,
.prov-node--source,
.prov-node--audit {
  --node-accent: var(--color-chart-slate);
}

.prov-node--context,
.prov-node--model_intent {
  --node-accent: var(--color-chart-secondary);
}

.prov-node--action,
.prov-node--resource,
.prov-node--approval,
.prov-node--review,
.prov-node--action_critic {
  --node-accent: var(--color-chart-warning);
}

.prov-node--rule,
.prov-node--decision {
  --node-accent: var(--color-chart-danger);
}

.prov-node--policy,
.prov-node--runtime_result,
.prov-node--event {
  --node-accent: var(--color-chart-primary);
}

.prov-node header {
  align-items: center;
  display: grid;
  gap: var(--space-2);
  grid-template-columns: auto minmax(0, 1fr) auto;
}

.prov-node__icon {
  align-items: center;
  background: color-mix(in srgb, var(--node-accent) 10%, var(--color-surface));
  border-radius: var(--radius-1);
  color: var(--node-accent);
  display: inline-flex;
  height: 1.55rem;
  justify-content: center;
  width: 1.55rem;
}

.prov-node__kind,
.prov-node__phase {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.prov-node__phase {
  font-family: var(--font-family-mono);
}

.prov-node__label {
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  color: var(--color-text);
  display: -webkit-box;
  font-size: var(--font-size-13);
  line-height: var(--line-height-ui);
  overflow: hidden;
  overflow-wrap: anywhere;
}

.prov-node__summary {
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  color: var(--color-text-muted);
  display: -webkit-box;
  font-size: var(--font-size-11);
  line-height: var(--line-height-ui);
  overflow: hidden;
  overflow-wrap: anywhere;
}

.prov-node__badge {
  align-self: end;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-pill);
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  justify-self: start;
  max-width: 100%;
  overflow: hidden;
  padding: 0.1rem var(--space-2);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.provenance-workbench--overview .prov-node__summary,
.provenance-workbench--overview .prov-node__badge,
.provenance-workbench--standard .prov-node__summary {
  display: none;
}

.provenance-flow :deep(.vue-flow__handle) {
  background: var(--node-accent);
  border: 2px solid var(--color-surface);
  height: 0.48rem;
  opacity: 0.75;
  width: 0.48rem;
}

.provenance-layout-status,
.provenance-filter-empty {
  align-items: center;
  background: color-mix(in srgb, var(--color-surface) 94%, transparent);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  box-shadow: var(--shadow-subtle);
  color: var(--color-text-muted);
  display: flex;
  font-size: var(--font-size-12);
  gap: var(--space-2);
  left: 50%;
  padding: var(--space-2) var(--space-3);
  position: absolute;
  top: var(--space-4);
  transform: translateX(-50%);
  z-index: 5;
}

.provenance-layout-status svg {
  animation: provenance-spin 0.8s linear infinite;
}

.provenance-filter-empty {
  flex-direction: column;
  top: 45%;
}

.provenance-filter-empty p {
  margin: 0;
}

.provenance-filter-empty button {
  background: transparent;
  border: 0;
  color: var(--color-link);
  cursor: pointer;
  font-weight: var(--font-weight-semibold);
}

.provenance-hidden-count {
  background: color-mix(in srgb, var(--color-shell) 91%, transparent);
  border-radius: var(--radius-pill);
  bottom: var(--space-4);
  color: var(--color-shell-text);
  font-size: var(--font-size-11);
  left: 50%;
  padding: var(--space-1) var(--space-3);
  pointer-events: none;
  position: absolute;
  transform: translateX(-50%);
  z-index: 4;
}

.provenance-empty {
  color: var(--color-text-subtle);
  margin: 0;
  padding: var(--space-8);
  text-align: center;
}

@keyframes provenance-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 74rem) {
  .provenance-toolbar {
    grid-template-columns: minmax(14rem, 1fr) auto;
  }

  .provenance-toolbar__actions {
    grid-column: 1 / -1;
    justify-self: start;
  }
}

@media (max-width: 68rem) {
  .provenance-workbench {
    grid-template-rows: auto auto minmax(38rem, 72vh);
  }

  .provenance-toolbar {
    grid-template-columns: 1fr;
  }

  .provenance-toolbar__search {
    max-width: none;
  }

  .provenance-toolbar__select,
  .provenance-toolbar__actions {
    justify-self: stretch;
  }

  .provenance-toolbar__select select {
    flex: 1;
  }

  .provenance-toolbar__actions {
    overflow-x: auto;
  }

  .provenance-toolbar__actions button {
    flex: 1 0 auto;
  }

  .provenance-phases {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .provenance-phases button:nth-child(3) {
    border-left: 0;
  }

  .provenance-phases button:nth-child(n + 3) {
    border-top: 1px solid var(--color-border);
  }
}

@media (prefers-reduced-motion: reduce) {
  .provenance-flow :deep(.vue-flow__node),
  .provenance-flow :deep(.vue-flow__edge-path),
  .provenance-flow :deep(.vue-flow__edge-text) {
    transition: none;
  }

  .provenance-layout-status svg {
    animation: none;
  }
}
</style>
