<template>
  <aside class="provenance-inspector" aria-labelledby="provenance-inspector-title">
    <header>
      <h3 id="provenance-inspector-title">节点详情</h3>
    </header>

    <template v-if="node">
      <div class="provenance-inspector__identity">
        <span>{{ kindLabel(node.kind) }}</span>
        <strong>{{ nodeDisplayLabel }}</strong>
        <p v-if="summary">{{ summary }}</p>
        <p v-if="sourceMode === 'mock'" class="provenance-inspector__mock-note">
          MOCK PREVIEW · 固定合成内容入口，不是真实运行结果
        </p>
      </div>

      <dl>
        <div>
          <dt>处理阶段</dt>
          <dd>{{ phaseLabel }}</dd>
        </div>
        <div>
          <dt>证据时间</dt>
          <dd>{{ formatDashboardDateTime(node.timestamp) }}</dd>
        </div>
        <div>
          <dt>节点 ID</dt>
          <dd>
            <code>{{ node.nodeId }}</code>
          </dd>
        </div>
        <div>
          <dt>引用</dt>
          <dd>
            <code>{{ node.refId || "未记录" }}</code>
          </dd>
        </div>
        <div>
          <dt>上游 / 下游</dt>
          <dd>{{ incomingCount }} / {{ outgoingCount }}</dd>
        </div>
        <div>
          <dt>状态</dt>
          <dd>{{ status || "未记录" }}</dd>
        </div>
        <div v-if="sourceMode">
          <dt>来源模式</dt>
          <dd>{{ sourceMode === "mock" ? "Mock Preview" : sourceMode }}</dd>
        </div>
        <div v-if="presentationNode">
          <dt>Availability</dt>
          <dd>{{ presentationNode.semantics.availability }}</dd>
        </div>
        <div v-if="presentationNode">
          <dt>Certainty</dt>
          <dd>{{ presentationNode.semantics.certainty }}</dd>
        </div>
        <div v-if="presentationNode">
          <dt>Authority</dt>
          <dd>{{ presentationNode.semantics.factAuthority }}</dd>
        </div>
        <div v-if="presentationNode?.nodeKind === 'source'">
          <dt>Source / Trust</dt>
          <dd>
            {{ presentationNode.normalizedCtSourceType ?? "unknown" }} /
            {{ presentationNode.trust }}
          </dd>
        </div>
        <div v-if="presentationNode?.taints.length">
          <dt>Taints</dt>
          <dd>{{ presentationNode.taints.join(" · ") }}</dd>
        </div>
        <div v-if="adjacentCertainties.length">
          <dt>关系确定性</dt>
          <dd>{{ adjacentCertainties.join(" · ") }}</dd>
        </div>
      </dl>

      <button
        v-if="eventId"
        type="button"
        class="provenance-inspector__event"
        @click="emit('select-event', eventId)"
      >
        查看关联事件
      </button>

      <details v-if="Object.keys(safeMetadata).length">
        <summary>结构化节点证据</summary>
        <StructuredDataView :value="safeMetadata" />
      </details>
    </template>

    <div v-else class="provenance-inspector__empty">
      <MousePointer2 :size="20" aria-hidden="true" />
      <p>选择图中节点，检查其证据、上下游关系与关联审计。</p>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { MousePointer2 } from "@lucide/vue";
import { computed } from "vue";

import type {
  NormalizedAuditEvidence,
  ProvenanceGraph,
  ProvenanceNode,
} from "../../types/dashboard";
import type {
  ElementSourceMode,
  ProvenancePresentationViewModel,
} from "../../types/runtime-supervision";
import { redactSensitiveData } from "../../utils/data-redaction";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getEventTypeLabel,
} from "../../utils/dashboard-formatters";
import { resolveProvenanceAuditId } from "../../utils/provenance";
import { formatRuleIdsInTextForDisplay } from "../../utils/rule-display";
import StructuredDataView from "../common/StructuredDataView.vue";

defineOptions({ name: "ProvenanceInspector" });
const props = defineProps<{
  elementSourceMode: ElementSourceMode;
  events: NormalizedAuditEvidence[];
  graph: ProvenanceGraph;
  node?: ProvenanceNode;
  presentation: ProvenancePresentationViewModel;
}>();
const emit = defineEmits<{ "select-event": [eventId: string] }>();

const kindLabels: Record<string, string> = {
  action: "受控动作",
  action_critic: "复核",
  approval: "人工审批",
  audit: "审计记录",
  config_audit: "配置审计",
  context: "上下文",
  decision: "安全决定",
  event: "运行时事件",
  model_intent: "模型意图",
  policy: "当时生效的策略",
  resource: "资源目标",
  review: "风险组合",
  rule: "命中规则",
  runtime_result: "运行时结果",
  source: "来源",
  task: "原始任务",
};

function kindLabel(kind: string): string {
  return kindLabels[kind] ?? kind;
}

const nodeDisplayLabel = computed(() => {
  if (!props.node) return "";
  if (
    props.node.kind === "decision" &&
    ["allow", "ask", "deny", "unknown"].includes(props.node.label)
  ) {
    return getDecisionLabel(props.node.label as "allow" | "ask" | "deny" | "unknown");
  }
  if (
    props.node.kind === "event" ||
    props.node.kind === "audit" ||
    props.node.kind === "config_audit"
  ) {
    return getEventTypeLabel(props.node.label);
  }
  return formatRuleIdsInTextForDisplay(props.node.label);
});

const summary = computed(() => {
  const value = props.node?.metadata.summary;
  return typeof value === "string" ? formatRuleIdsInTextForDisplay(value) : "";
});
const status = computed(() => {
  const value = props.node?.metadata.status;
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
});
const sourceMode = computed(() => props.elementSourceMode);
const presentationNode = computed(() =>
  props.presentation.nodes.find((item) => item.provenanceNodeId === props.node?.nodeId),
);
const adjacentCertainties = computed(() => [
  ...new Set(
    props.presentation.edges
      .filter(
        (edge) =>
          edge.sourceNodeId === props.node?.nodeId || edge.targetNodeId === props.node?.nodeId,
      )
      .map((edge) => edge.certainty),
  ),
]);
const phaseLabel = computed(() => {
  const phase = props.node?.metadata.phase;
  const labels: Record<string, string> = {
    context_intent: "02 · 上下文与模型意图",
    input_trust: "01 · 输入与信任",
    outcome_audit: "04 · 执行结果与审计",
    tool_policy: "03 · 工具、资源与策略",
  };
  return typeof phase === "string" ? (labels[phase] ?? phase) : "未记录";
});
const incomingCount = computed(
  () => props.graph.edges.filter((edge) => edge.targetNodeId === props.node?.nodeId).length,
);
const outgoingCount = computed(
  () => props.graph.edges.filter((edge) => edge.sourceNodeId === props.node?.nodeId).length,
);
const eventId = computed(() => resolveProvenanceAuditId(props.node, props.events));
const safeMetadata = computed(() => {
  const metadata = props.node?.metadata ?? {};
  const visibleMetadata = Object.fromEntries(
    Object.entries(metadata).filter(
      ([key, value]) =>
        key !== "source" &&
        ![
          "availability",
          "certainty",
          "decision_authority",
          "fact_authority",
          "flow_origin",
          "flow_strength",
          "source_mode",
          "taints",
          "trust",
        ].includes(key) &&
        !key.startsWith("_") &&
        value !== undefined &&
        value !== null &&
        value !== "",
    ),
  );
  return redactSensitiveData(visibleMetadata) as Record<string, unknown>;
});
</script>

<style scoped lang="scss">
.provenance-inspector {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-4);
  min-height: 0;
  padding: var(--space-4);
}

.provenance-inspector > header {
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  padding-bottom: var(--space-3);
}

.provenance-inspector h3 {
  font-size: var(--font-size-16);
  margin: 0;
}

.provenance-inspector__identity {
  display: grid;
  gap: var(--space-2);
}

.provenance-inspector__identity > span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
}

.provenance-inspector__identity strong {
  font-size: var(--font-size-16);
  overflow-wrap: anywhere;
}

.provenance-inspector__identity p {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  margin: 0;
}

.provenance-inspector__identity .provenance-inspector__mock-note {
  background: color-mix(in srgb, var(--color-warning) 10%, var(--color-surface));
  border: 1px dashed var(--color-warning-border);
  border-radius: var(--radius-1);
  color: var(--color-warning-strong);
  padding: var(--space-2);
}

.provenance-inspector dl {
  display: grid;
  margin: 0;
}

.provenance-inspector dl > div {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-2) 0;
}

.provenance-inspector dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.provenance-inspector dd {
  font-size: var(--font-size-12);
  margin: 0;
  overflow-wrap: anywhere;
}

.provenance-inspector__event {
  background: var(--color-active);
  border: 0;
  border-radius: var(--radius-2);
  color: var(--color-active-text);
  cursor: pointer;
  font-weight: var(--font-weight-semibold);
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}

.provenance-inspector__event:focus-visible,
.provenance-inspector summary:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: 2px;
}

.provenance-inspector details {
  border-top: 1px solid var(--color-border);
  min-width: 0;
  padding-top: var(--space-3);
}

.provenance-inspector summary {
  align-items: center;
  color: var(--color-link);
  cursor: pointer;
  display: flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  margin-bottom: var(--space-3);
  min-height: 2.25rem;
}

.provenance-inspector__empty {
  align-content: center;
  color: var(--color-text-subtle);
  display: grid;
  gap: var(--space-2);
  justify-items: center;
  min-height: 14rem;
  text-align: center;
}

.provenance-inspector__empty p {
  font-size: var(--font-size-12);
  margin: 0;
  max-width: 13rem;
}
</style>
