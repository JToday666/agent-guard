<template>
  <div class="provenance-wrap">
    <template v-if="graph.nodes.length">
      <div class="provenance-legend" aria-label="溯源图图例">
        <span
          v-for="item in legendItems"
          :key="item.kind"
          :class="`provenance-legend__item--${item.kind}`"
        >
          <i aria-hidden="true"></i>{{ item.label }}
        </span>
      </div>
      <VueFlow
        :nodes="flowNodes"
        :edges="flowEdges"
        :fit-view-on-init="true"
        :nodes-connectable="false"
        :nodes-draggable="false"
        :elements-selectable="true"
        :fit-view-options="{ padding: 0.18 }"
        :zoom-on-scroll="true"
        class="provenance-flow"
        @node-click="handleNodeClick"
      >
        <Background pattern-color="var(--color-chart-grid)" :gap="20" :size="1" />
        <Controls :show-interactive="false" />
        <template #node-provenance="{ data }">
          <div
            class="prov-node"
            :class="[
              `prov-node--${data.kind}`,
              { 'prov-node--selected': data.nodeId === selectedNodeId },
            ]"
            :title="displayText(data.label)"
          >
            <span class="prov-node__kind">{{ nodeLane(data.metadata, data.kind) }}</span>
            <span class="prov-node__label">{{ displayText(data.label) }}</span>
            <span v-if="nodeSummary(data.metadata)" class="prov-node__summary">{{
              nodeSummary(data.metadata)
            }}</span>
            <span v-if="nodeMetaBadge(data.metadata)" class="prov-node__badge">{{
              nodeMetaBadge(data.metadata)
            }}</span>
          </div>
        </template>
      </VueFlow>
    </template>
    <p v-else class="provenance-empty">该证据链暂无溯源节点</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { VueFlow, type Node, type Edge } from "@vue-flow/core";
import { Background } from "@vue-flow/background";
import { Controls } from "@vue-flow/controls";
import dagre from "@dagrejs/dagre";
import type { ProvenanceGraph } from "../../types/dashboard";
import { getDecisionLabel } from "../../utils/dashboard-formatters";
import { formatRuleIdsInTextForDisplay } from "../../utils/rule-display";

defineOptions({ name: "ProvenanceGraph" });

const props = defineProps<{
  graph: ProvenanceGraph;
  selectedNodeId?: string;
}>();

const emit = defineEmits<{
  "select-node": [nodeId: string];
}>();

const legendItems = [
  { kind: "audit", label: "任务与资源" },
  { kind: "event", label: "Agent 行为" },
  { kind: "decision", label: "规则与结果" },
  { kind: "action_critic", label: "复核与审批" },
  { kind: "config_audit", label: "上下文" },
] as const;

function kindLabel(kind: string): string {
  return (
    (
      {
        event: "事件",
        decision: "决策",
        audit: "审计",
        config_audit: "配置审计",
        action_critic: "二次审查",
      } as Record<string, string>
    )[kind] ?? kind
  );
}

function metadataValue(metadata: Record<string, unknown>, key: string): string {
  const value = metadata[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function displayText(value: string): string {
  return formatRuleIdsInTextForDisplay(value);
}

function nodeLane(metadata: Record<string, unknown>, kind: string): string {
  return metadataValue(metadata, "lane") || kindLabel(kind);
}

function nodeSummary(metadata: Record<string, unknown>): string {
  const summary = displayText(metadataValue(metadata, "summary"));
  return summary.length > 54 ? `${summary.slice(0, 54)}…` : summary;
}

function nodeMetaBadge(metadata: Record<string, unknown>): string {
  const riskScore = metadataValue(metadata, "riskScore");
  if (riskScore) return `风险 ${riskScore}`;
  const decision = metadataValue(metadata, "decision");
  if (decision === "allow" || decision === "ask" || decision === "deny")
    return getDecisionLabel(decision);
  const status = metadataValue(metadata, "status");
  if (status)
    return (
      (
        {
          pending: "待审批",
          allowed: "人工单次放行",
          denied: "已拒绝并阻断",
        } as Record<string, string>
      )[status] ?? status
    );
  return "";
}

const NODE_W = 260;
const NODE_H = 120;
const ENHANCED_STEP_X = 328;
const ENHANCED_TOP_Y = 96;
const ENHANCED_BOTTOM_Y = 296;

function enhancedMockPosition(nodeId: string, index: number): { x: number; y: number } {
  const suffix = nodeId.split(":").at(-1) ?? "";
  const positions: Record<string, { column: number; row: "top" | "bottom" | "middle" }> = {
    task: { column: 0, row: "middle" },
    context: { column: 1, row: "top" },
    action: { column: 2, row: "top" },
    resource: { column: 3, row: "top" },
    policy: { column: 4, row: "top" },
    critic: { column: 4, row: "bottom" },
    approval: { column: 5, row: "bottom" },
    outcome: { column: 6, row: "bottom" },
  };
  const known = positions[suffix];
  if (known) {
    return {
      x: 28 + known.column * ENHANCED_STEP_X,
      y: known.row === "top" ? ENHANCED_TOP_Y : known.row === "bottom" ? ENHANCED_BOTTOM_Y : 196,
    };
  }
  if (nodeId.includes(":event:")) {
    return { x: 28 + 3 * ENHANCED_STEP_X, y: ENHANCED_BOTTOM_Y + Math.max(0, index - 4) * 72 };
  }
  return { x: 28 + index * ENHANCED_STEP_X, y: ENHANCED_BOTTOM_Y };
}

const isEnhancedMockGraph = computed(
  () =>
    props.graph.nodes.length >= 8 &&
    props.graph.nodes.every((node) => node.metadata.source === "mock"),
);

const flowNodes = computed<Node[]>(() => {
  if (isEnhancedMockGraph.value) {
    return props.graph.nodes.map((n, index) => ({
      id: n.nodeId,
      type: "provenance",
      position: enhancedMockPosition(n.nodeId, index),
      data: { ...n },
    }));
  }

  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 90, ranksep: 180, marginx: 36, marginy: 72 });
  for (const n of props.graph.nodes) g.setNode(n.nodeId, { width: NODE_W, height: NODE_H });
  for (const e of props.graph.edges) g.setEdge(e.sourceNodeId, e.targetNodeId);
  dagre.layout(g);
  return props.graph.nodes.map((n) => {
    const pos = g.node(n.nodeId);
    return {
      id: n.nodeId,
      type: "provenance",
      position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 },
      data: { ...n },
    };
  });
});

function edgeLabel(relation: string): string {
  return (
    (
      {
        生成审计: "审计",
        规则判断: "判断",
        风险复核: "复核",
        请求审批: "审批",
        形成结果: "结果",
      } as Record<string, string>
    )[relation] ?? ""
  );
}

const flowEdges = computed<Edge[]>(() =>
  props.graph.edges.map((e) => ({
    id: e.edgeId,
    source: e.sourceNodeId,
    target: e.targetNodeId,
    label: edgeLabel(e.relation),
    style: { stroke: "var(--color-border-strong)", strokeWidth: 1.5 },
    labelBgBorderRadius: 4,
    labelBgPadding: [2, 4],
    labelBgStyle: { fill: "var(--color-surface)", fillOpacity: 0.96 },
    labelStyle: { fontSize: "10px", fill: "var(--color-text-muted)", fontWeight: 640 },
  })),
);

function handleNodeClick(event: { node: { id: string } }) {
  emit("select-node", event.node.id);
}
</script>

<style>
@import "@vue-flow/core/dist/style.css";
@import "@vue-flow/core/dist/theme-default.css";
@import "@vue-flow/controls/dist/style.css";
</style>

<style scoped lang="scss">
.provenance-wrap {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  height: clamp(28rem, 52vh, 32rem);
  overflow: hidden;
  position: relative;
}

.provenance-legend {
  align-items: center;
  background: color-mix(in srgb, var(--color-surface) 92%, transparent);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  box-shadow: var(--shadow-subtle);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2) var(--space-3);
  left: var(--space-3);
  max-width: calc(100% - 6rem);
  padding: var(--space-2) var(--space-3);
  position: absolute;
  top: var(--space-3);
  z-index: 5;
}

.provenance-legend span {
  align-items: center;
  color: var(--color-text-muted);
  display: inline-flex;
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-1);
}

.provenance-legend i {
  border-radius: 999px;
  display: inline-block;
  height: 0.55rem;
  width: 0.55rem;
}

.provenance-legend__item--event i {
  background: var(--color-node-event);
}
.provenance-legend__item--decision i {
  background: var(--color-node-decision);
}
.provenance-legend__item--audit i {
  background: var(--color-node-audit);
}
.provenance-legend__item--config_audit i {
  background: var(--color-node-config-audit);
}
.provenance-legend__item--action_critic i {
  background: var(--color-node-action-critic);
}

.provenance-flow {
  background: var(--color-surface-muted);
  height: 100%;
  width: 100%;
}

.prov-node {
  background: var(--color-surface);
  border: 1.5px solid var(--color-border);
  border-radius: var(--radius-2);
  box-sizing: border-box;
  cursor: pointer;
  display: grid;
  gap: 0.22rem;
  height: 7.5rem;
  width: 16.25rem;
  padding: 0.65rem 0.78rem 0.72rem;
  transition:
    box-shadow var(--transition-fast),
    border-color var(--transition-fast);

  &:hover {
    border-color: var(--color-active);
    box-shadow: 0 0 0 2px var(--color-active-soft);
  }
  &--selected {
    border-color: var(--color-active);
    box-shadow: 0 0 0 3px var(--color-active-soft);
  }
  &--event {
    border-left: 3px solid var(--color-node-event);
  }
  &--decision {
    border-left: 3px solid var(--color-node-decision);
  }
  &--audit {
    border-left: 3px solid var(--color-node-audit);
  }
  &--config_audit {
    border-left: 3px solid var(--color-node-config-audit);
  }
  &--action_critic {
    border-left: 3px solid var(--color-node-action-critic);
  }
}

.prov-node__kind {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.prov-node__label {
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  color: var(--color-text);
  display: -webkit-box;
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  line-height: var(--line-height-ui);
  overflow: hidden;
  overflow-wrap: anywhere;
  white-space: normal;
  word-break: break-word;
}

.prov-node__summary {
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  color: var(--color-text-muted);
  display: -webkit-box;
  font-size: var(--font-size-11);
  line-height: var(--line-height-ui);
  overflow: hidden;
  overflow-wrap: anywhere;
  white-space: normal;
  word-break: break-word;
}

.prov-node__badge {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-pill);
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
  justify-self: start;
  margin-top: var(--space-1);
  padding: 0.1rem var(--space-2);
}

.provenance-empty {
  align-items: center;
  color: var(--color-text-subtle);
  display: flex;
  font-size: var(--font-size-13);
  height: 100%;
  justify-content: center;
  margin: 0;
}
</style>
