<template>
  <div class="event-evidence">
    <section class="event-evidence__risk">
      <div class="risk-score" :class="`risk-score--${event.severity}`">
        <span>风险分数</span><strong>{{ event.riskScore }}</strong><small>/ 100</small>
      </div>
      <dl>
        <div><dt>决策</dt><dd><StatusBadge :label="getDecisionLabel(event.decision)" :tone="getDecisionTone(event.decision)" /></dd></div>
        <div><dt>严重性</dt><dd>{{ getRiskSeverityLabel(event.severity) }}</dd></div>
        <div><dt>阻断</dt><dd>{{ event.blocked ? "已阻断" : "未阻断" }}</dd></div>
        <div><dt>运行时</dt><dd>{{ event.runtime }}</dd></div>
      </dl>
    </section>

    <section class="event-evidence__section">
      <h3>任务与行为</h3>
      <dl class="evidence-copy">
        <div><dt>用户任务</dt><dd>{{ event.userTask ?? "未提供" }}</dd></div>
        <div><dt>Agent 行为</dt><dd>{{ event.agentAction ?? "未提供" }}</dd></div>
        <div><dt>判定原因</dt><dd>{{ event.reason }}</dd></div>
        <div><dt>目标资源</dt><dd><code>{{ event.resource }}</code></dd></div>
      </dl>
    </section>

    <section v-if="event.resourceTargets.length > 1" class="event-evidence__section">
      <h3>资源目标</h3>
      <ul class="resource-list">
        <li v-for="target in event.resourceTargets" :key="target"><code>{{ target }}</code></li>
      </ul>
    </section>

    <section class="event-evidence__section">
      <h3>命中规则</h3>
      <div class="rule-list">
        <span v-for="rule in event.ruleHits" :key="rule">{{ ruleLabel(rule) }}</span>
        <span v-if="!event.ruleHits.length">未命中阻断规则</span>
      </div>
    </section>

    <section class="event-evidence__section">
      <h3>关联证据</h3>
      <div class="evidence-links">
        <RouterLink :to="`/evidence/${event.traceId}`">完整证据链</RouterLink>
        <button type="button" @click="copy(event.traceId, '证据链 ID')">复制证据链 ID</button>
        <RouterLink v-if="event.caseId" :to="{ path: '/evaluation', query: { case_id: event.caseId } }">评测样本</RouterLink>
        <RouterLink v-if="event.approvalId" :to="`/approvals/${event.approvalId}`">关联审批</RouterLink>
      </div>
      <span v-if="copyStatus" class="copy-status" role="status">{{ copyStatus }}</span>
    </section>

    <slot />
    <StructuredDataView :value="safeRawEvent" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";

import type { AuditEventRow } from "../types/dashboard";
import { redactSensitiveData } from "../utils/data-redaction";
import {
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
} from "../utils/dashboard-formatters";
import StatusBadge from "./StatusBadge.vue";
import StructuredDataView from "./StructuredDataView.vue";
import { prepareEvidenceDataForDisplay, ruleLabel } from "../utils/rule-display";

defineOptions({ name: "EventEvidence" });
const props = defineProps<{ event: AuditEventRow }>();
const copyStatus = ref("");
const safeRawEvent = computed(() => prepareEvidenceDataForDisplay(redactSensitiveData(props.event.raw ?? props.event)));

async function copy(value: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    copyStatus.value = `${label} 已复制`;
  } catch {
    copyStatus.value = `${label} 复制失败`;
  }
}
</script>

<style scoped lang="scss">
.event-evidence { display: grid; gap: var(--space-5); }
.event-evidence__risk { display: grid; gap: var(--space-4); grid-template-columns: 7rem minmax(0, 1fr); }
.risk-score { border-left: 3px solid var(--color-active); display: grid; padding-left: var(--space-3); }
.risk-score span, .risk-score small { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.risk-score strong { font-size: 2rem; line-height: 1.05; }
.risk-score--critical, .risk-score--high { border-color: var(--color-danger); color: var(--color-danger); }
.risk-score--medium { border-color: var(--color-warning); color: var(--color-warning); }
.event-evidence__risk dl { display: grid; gap: var(--space-2); margin: 0; }
.event-evidence__risk dl > div { align-items: center; display: flex; gap: var(--space-3); justify-content: space-between; }
	.event-evidence dt { color: var(--color-text-muted); font-size: var(--font-size-12); font-weight: var(--font-weight-semibold); }
	.event-evidence dd { margin: 0; overflow-wrap: anywhere; }
.event-evidence__section { border-top: 1px solid var(--color-border); display: grid; gap: var(--space-3); padding-top: var(--space-4); }
.event-evidence h3 { font-size: var(--font-size-14); margin: 0; }
.evidence-copy { display: grid; gap: var(--space-3); margin: 0; }
.evidence-copy > div { display: grid; gap: var(--space-1); }
	.evidence-copy dd { color: var(--color-text); line-height: 1.55; }
.rule-list, .evidence-links { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.resource-list { display: grid; gap: var(--space-2); list-style: none; margin: 0; padding: 0; }
.resource-list li { background: var(--color-surface-muted); border: 1px solid var(--color-border); border-radius: var(--radius-2); padding: var(--space-2); }
.resource-list code { overflow-wrap: anywhere; }
.rule-list span { background: var(--color-surface-muted); border: 1px solid var(--color-border); border-radius: var(--radius-pill); font-size: var(--font-size-11); padding: var(--space-1) var(--space-2); }
.evidence-links a, .evidence-links button { background: transparent; border: 0; color: var(--color-link); cursor: pointer; font-size: var(--font-size-12); padding: 0; text-decoration: none; }
.copy-status { color: var(--color-success); font-size: var(--font-size-12); }
@media (max-width: 420px) { .event-evidence__risk { grid-template-columns: 1fr; } }
</style>
