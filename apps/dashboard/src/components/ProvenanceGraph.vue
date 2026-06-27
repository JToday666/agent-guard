<template>
  <div class="provenance-wrap">
    <template v-if="graph.nodes.length">
      <VueFlow
        :nodes="flowNodes"
        :edges="flowEdges"
        :fit-view-on-init="true"
        :nodes-connectable="false"
        :nodes-draggable="false"
        :elements-selectable="true"
        :zoom-on-scroll="true"
        class="provenance-flow"
        @node-click="handleNodeClick"
      >
        <Background pattern-color="#dce4ee" :gap="20" :size="1" />
        <Controls :show-interactive="false" />
        <template #node-provenance="{ data }">
          <div
            class="prov-node"
            :class="[`prov-node--${data.kind}`, { 'prov-node--selected': data.nodeId === selectedNodeId }]"
            :title="data.label"
          >
            <span class="prov-node__kind">{{ kindLabel(data.kind) }}</span>
            <span class="prov-node__label">{{ data.label }}</span>
          </div>
        </template>
      </VueFlow>
    </template>
    <p v-else class="provenance-empty">该 Trace 暂无溯源节点</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { VueFlow, type Node, type Edge } from "@vue-flow/core";
import { Background } from "@vue-flow/background";
import { Controls } from "@vue-flow/controls";
import dagre from "@dagrejs/dagre";
import type { ProvenanceGraph } from "../types/dashboard";

defineOptions({ name: "ProvenanceGraph" });

const props = defineProps<{
  graph: ProvenanceGraph;
  selectedNodeId?: string;
}>();

const emit = defineEmits<{
  "select-node": [nodeId: string];
}>();

function kindLabel(kind: string): string {
  return ({
    event: "事件",
    decision: "决策",
    audit: "审计",
    config_audit: "配置审计",
    action_critic: "二次审查",
  } as Record<string, string>)[kind] ?? kind;
}

const NODE_W = 160;
const NODE_H = 60;

const flowNodes = computed<Node[]>(() => {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 40, ranksep: 80, marginx: 20, marginy: 20 });
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

const flowEdges = computed<Edge[]>(() =>
  props.graph.edges.map((e) => ({
    id: e.edgeId,
    source: e.sourceNodeId,
    target: e.targetNodeId,
    label: e.relation,
    style: { stroke: "var(--color-border-strong)", strokeWidth: 1.5 },
    labelStyle: { fontSize: "11px", fill: "var(--color-text-subtle)" },
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
  height: 28rem;
  overflow: hidden;
  position: relative;
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
  cursor: pointer;
  display: grid;
  gap: 0.2rem;
  min-width: 9rem;
  max-width: 10rem;
  padding: 0.5rem 0.75rem;
  transition: box-shadow var(--transition-fast), border-color var(--transition-fast);

  &:hover { border-color: var(--color-active); box-shadow: 0 0 0 2px var(--color-active-soft); }
  &--selected { border-color: var(--color-active); box-shadow: 0 0 0 3px var(--color-active-soft); }
  &--event { border-left: 3px solid var(--color-node-event); }
  &--decision { border-left: 3px solid var(--color-node-decision); }
  &--audit { border-left: 3px solid var(--color-node-audit); }
  &--config_audit { border-left: 3px solid var(--color-node-config-audit); }
  &--action_critic { border-left: 3px solid var(--color-node-action-critic); }
}

.prov-node__kind {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.prov-node__label {
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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
