<template>
  <div class="event-evidence">
    <section class="event-evidence__risk">
      <div class="risk-score" :class="`risk-score--${event.severity}`">
        <span>风险分数</span><strong>{{ event.riskScore ?? "--" }}</strong
        ><small>{{ event.riskScore === null ? "未记录" : "/ 100" }}</small>
      </div>
      <dl>
        <div>
          <dt>决策</dt>
          <dd>
            <StatusBadge
              :label="getDecisionLabel(event.decision)"
              :tone="getDecisionTone(event.decision)"
            />
          </dd>
        </div>
        <div>
          <dt>严重性</dt>
          <dd>{{ getRiskSeverityLabel(event.severity) }}</dd>
        </div>
        <div>
          <dt>运行时</dt>
          <dd>{{ getRuntimeLabel(event.runtime) }}</dd>
        </div>
      </dl>
    </section>

    <section v-if="normalized" class="event-evidence__section">
      <h3>运行时证据</h3>
      <dl class="evidence-copy">
        <div>
          <dt>记录类型</dt>
          <dd>{{ recordTypeLabel }}</dd>
        </div>
        <div>
          <dt>干预方式</dt>
          <dd>{{ getInterventionLabel(normalized.intervention) }}</dd>
        </div>
        <div>
          <dt>执行状态</dt>
          <dd>
            {{
              getExecutionStatusLabel(normalized.execution.status, {
                decision: normalized.decision,
                intervention: normalized.intervention,
              })
            }}
          </dd>
        </div>
        <div>
          <dt>副作用</dt>
          <dd>{{ getSideEffectLabel(normalized.sideEffects) }}</dd>
        </div>
        <div>
          <dt>结果处置</dt>
          <dd>{{ getResultDispositionLabel(normalized.resultDisposition) }}</dd>
        </div>
      </dl>
      <p class="event-evidence__caveat">
        策略决定与实际执行结果分别记录；没有运行时证据时，不推断动作是否执行或产生副作用。
      </p>
    </section>

    <section v-if="normalized" class="event-evidence__section">
      <h3>来源、参数与当时策略</h3>
      <dl class="evidence-copy">
        <div>
          <dt>来源</dt>
          <dd>
            {{ normalized.source.label ?? normalized.source.type ?? "未记录" }}
            <small
              >信任等级：{{ getTrustLevelLabel(normalized.source.trustLevel ?? "unknown") }}</small
            >
          </dd>
        </div>
        <div>
          <dt>工具参数</dt>
          <dd>
            <code>{{ formattedArguments }}</code>
          </dd>
        </div>
        <div>
          <dt>策略版本</dt>
          <dd>{{ policyLabel }}</dd>
        </div>
        <div>
          <dt>规范摘要</dt>
          <dd>
            <code>{{ normalized.policy.digest ?? policyDigestMissingText }}</code>
          </dd>
        </div>
      </dl>
    </section>

    <section class="event-evidence__section">
      <h3>任务与行为</h3>
      <dl class="evidence-copy">
        <div>
          <dt>用户任务</dt>
          <dd>{{ event.userTask ?? noDataNeeded("用户任务", "该事件类型不携带用户任务") }}</dd>
        </div>
        <div>
          <dt>Agent 行为</dt>
          <dd>
            {{ event.agentAction ?? noDataNeeded("Agent 行为描述", "该事件类型不携带行为描述") }}
          </dd>
        </div>
        <div>
          <dt>{{ contentPreviewLabel }}</dt>
          <dd>{{ contentPreviewValue }}</dd>
        </div>
        <div>
          <dt>判定原因</dt>
          <dd>{{ event.reason }}</dd>
        </div>
        <div>
          <dt>目标资源</dt>
          <dd>
            <code>{{ event.resource }}</code>
          </dd>
        </div>
      </dl>
    </section>

    <section v-if="event.resourceTargets.length > 1" class="event-evidence__section">
      <h3>资源目标</h3>
      <ul class="resource-list">
        <li v-for="target in event.resourceTargets" :key="target">
          <code>{{ target }}</code>
        </li>
      </ul>
    </section>

    <section class="event-evidence__section">
      <h3>命中规则</h3>
      <div class="rule-list">
        <span v-for="rule in event.ruleHits" :key="rule">{{ ruleLabel(rule) }}</span
        ><span v-if="!event.ruleHits.length">{{ ruleHitsEmptyText }}</span>
      </div>
    </section>

    <section class="event-evidence__section">
      <h3>关联证据</h3>
      <div class="evidence-links">
        <RouterLink :to="`/evidence/${event.traceId}`">完整证据链</RouterLink>
        <button type="button" @click="copy(event.traceId, '证据链 ID')">复制证据链 ID</button>
        <RouterLink
          v-if="event.caseId"
          :to="{ path: '/evaluation', query: { case_id: event.caseId } }"
          >评测样本</RouterLink
        >
        <RouterLink v-if="event.approvalId" :to="`/approvals/${event.approvalId}`"
          >关联审批</RouterLink
        >
      </div>
      <span v-if="copyStatus" class="copy-status" role="status">{{ copyStatus }}</span>
    </section>

    <slot />
    <StructuredDataView :value="safeRawEvent" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";

import type {
  AuditEventRow,
  AuditRecordType,
  NormalizedAuditEvidence,
} from "../../types/dashboard";
import {
  getExecutionStatusLabel,
  getInterventionLabel,
  getResultDispositionLabel,
  getSideEffectLabel,
} from "../../data/evidence/trace-evidence";
import { redactSensitiveData } from "../../utils/data-redaction";
import {
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
  getRuntimeLabel,
  getTrustLevelLabel,
} from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";
import StructuredDataView from "../common/StructuredDataView.vue";
import { prepareEvidenceDataForDisplay, ruleLabel } from "../../utils/rule-display";
import { noDataNeeded } from "../../utils/missing-data-display";
import { serializeStructuredData } from "../../utils/structured-data";

defineOptions({ name: "EventEvidence" });
const props = defineProps<{ event: AuditEventRow; normalized?: NormalizedAuditEvidence }>();
const copyStatus = ref("");
const safeRawEvent = computed(() =>
  prepareEvidenceDataForDisplay(redactSensitiveData(props.event.raw ?? props.event)),
);
const recordTypeLabel = computed(() => {
  const labels: Record<AuditRecordType, string> = {
    config_audit: "配置审计",
    policy_evaluation: "策略判定",
    runtime_observation: "运行时观察",
    runtime_outcome: "运行时结果",
    unknown: "未记录",
  };
  return labels[props.normalized?.recordType ?? "unknown"];
});
// 模型最终回复 / 外发消息正文：仅 model_output_produced 与
// message_send_proposed 携带；历史审计记录缺失该键时按①正常无数据处理。
const contentPreviewLabel = computed(() =>
  props.event.eventType === "message_send_proposed" ? "外发消息内容" : "模型输出内容",
);
const contentPreviewValue = computed(() => {
  const preview = props.normalized?.contentPreview;
  if (preview) return preview;
  return noDataNeeded("输出内容", "该事件类型不携带输出内容");
});
const formattedArguments = computed(() => {
  const normalized = props.normalized;
  if (normalized?.toolArguments) return serializeStructuredData(normalized.toolArguments);
  // 有工具名才是工具事件；非工具调用事件本就无工具参数（①正常无数据）。
  if (normalized?.toolName) return "工具参数未记录";
  return noDataNeeded("工具参数", "本记录非工具调用");
});
// ②按字段契约：策略引用应包含 digest，缺失属数据异常。
const policyDigestMissingText = "规范摘要缺失（策略引用应包含 digest，属数据异常）";
// 命中规则空列表按判定结果区分：allow 属①正常无数据；deny/ask 无命中则提示异常。
const ruleHitsEmptyText = computed(() => {
  if (props.event.decision === "allow") return noDataNeeded("命中规则", "动作为允许");
  if (props.event.decision === "deny" || props.event.decision === "ask") {
    return `异常：动作为${getDecisionLabel(props.event.decision)}，但未记录任何命中规则`;
  }
  return "未记录规则命中";
});
const policyLabel = computed(() => {
  const policy = props.normalized?.policy;
  if (!policy) return "未记录";
  const parts = [
    policy.bundleId,
    policy.version,
    policy.revision === null ? null : `修订 ${policy.revision}`,
  ].filter((value): value is string => Boolean(value));
  return parts.join(" / ") || "未记录";
});

async function copy(value: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    copyStatus.value = `${label} 已复制`;
  } catch {
    copyStatus.value = `${label} 复制失败`;
  }
  window.setTimeout(() => {
    copyStatus.value = "";
  }, 1600);
}
</script>

<style scoped lang="scss">
.event-evidence {
  display: grid;
  gap: var(--space-6);
}

.event-evidence__risk {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-4);
  grid-template-columns: 7rem minmax(0, 1fr);
  padding: var(--space-4);
}
.risk-score {
  border-left: 3px solid var(--color-active);
  display: grid;
  padding-left: var(--space-3);
}
.risk-score span,
.risk-score small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
}
.risk-score strong {
  font-size: 2rem;
  line-height: 1.05;
}
.risk-score--critical,
.risk-score--high {
  border-color: var(--color-danger);
  color: var(--color-danger);
}
.risk-score--medium {
  border-color: var(--color-warning);
  color: var(--color-warning);
}

.event-evidence__risk dl {
  display: grid;
  gap: var(--space-2);
  margin: 0;
}
.event-evidence__risk dl > div {
  align-items: center;
  display: flex;
  gap: var(--space-3);
  justify-content: space-between;
}

.event-evidence dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.event-evidence dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.event-evidence__section {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  padding-top: var(--space-4);
}
.event-evidence h3 {
  color: var(--color-text);
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  margin: 0;
}

.evidence-copy {
  display: grid;
  gap: 0;
  margin: 0;
}
.evidence-copy > div {
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-2) 0;
  &:last-child {
    border-bottom: 0;
  }
}
.evidence-copy dd {
  color: var(--color-text);
  display: grid;
  gap: var(--space-1);
  line-height: 1.65;
}

.evidence-copy dd small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.event-evidence__caveat {
  background: var(--color-warning-soft);
  border-left: 2px solid var(--color-warning);
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  margin: 0;
  padding: var(--space-2) var(--space-3);
}

.resource-list {
  border-top: 1px solid var(--color-border);
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}
.resource-list li {
  border-bottom: 1px solid var(--color-border);
  padding: var(--space-2) 0;
}
.resource-list code {
  overflow-wrap: anywhere;
}

.rule-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}
.rule-list span {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-1);
  font-size: var(--font-size-11);
  padding: var(--space-1) var(--space-2);
}

.evidence-links {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}
.evidence-links a,
.evidence-links button {
  align-items: center;
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  display: inline-flex;
  font-size: var(--font-size-12);
  min-height: 2.25rem;
  padding: 0 var(--space-3);
  text-decoration: none;
  &:hover {
    background: var(--color-surface-muted);
    border-color: var(--color-active);
  }
}
.copy-status {
  color: var(--color-success);
  font-size: var(--font-size-12);
}
</style>
