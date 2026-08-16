<template>
  <div class="evidence-dossier">
    <section>
      <header>
        <h3>动作与资源</h3>
      </header>
      <dl class="evidence-dossier__facts">
        <div>
          <dt>工具</dt>
          <dd>
            <code>{{ primary?.toolName ?? "未记录" }}</code>
          </dd>
        </div>
        <div>
          <dt>模型意图</dt>
          <dd>{{ primary?.modelIntent ?? "未记录" }}</dd>
        </div>
      </dl>
      <StructuredDataView
        v-if="primary?.toolArguments"
        :value="primary.toolArguments"
        class="evidence-dossier__structured"
      />
      <p v-else class="evidence-dossier__missing">工具参数未记录</p>
      <ul v-if="primary?.resources.length" class="resource-evidence-list">
        <li v-for="resource in primary.resources" :key="resource.id">
          <div>
            <strong>{{ resourceTypeLabel(resource.type) }}</strong>
            <span>
              {{ resourceDetail(resource.operation, resource.sensitivity) }}
            </span>
          </div>
          <code>{{ resource.value }}</code>
        </li>
      </ul>
      <p v-else class="evidence-dossier__missing">资源目标未记录</p>
    </section>

    <section>
      <header>
        <h3>命中规则与风险原因</h3>
      </header>
      <div class="risk-composition">
        <div>
          <span>聚合方法</span>
          <strong>{{ riskAggregationLabel }}</strong>
        </div>
        <div>
          <span>最终风险</span>
          <strong>{{
            primary?.risk.finalScore === null || primary?.risk.finalScore === undefined
              ? "未记录"
              : `${primary.risk.finalScore} / 100`
          }}</strong>
        </div>
        <div>
          <span>最终决定</span>
          <strong>{{ getDecisionEvidenceLabel(primary?.risk.finalDecision ?? "unknown") }}</strong>
        </div>
      </div>

      <ol v-if="primary?.risk.factors.length" class="risk-factor-list">
        <li v-for="factor in primary.risk.factors" :key="factor.id">
          <div>
            <strong>{{ factor.label }}</strong>
            <span>{{ factor.reason ?? "原因未记录" }}</span>
          </div>
          <div class="risk-factor-list__score">
            <span
              :style="{
                transform: `scaleX(${Math.min(1, Math.max(0, (factor.score ?? 0) / 100))})`,
              }"
            ></span>
            <b>{{ factor.score ?? "--" }}</b>
          </div>
        </li>
      </ol>
      <p v-else class="evidence-dossier__missing">结构化风险因子未记录</p>

      <ul v-if="primary?.ruleHits.length" class="rule-evidence-list">
        <li v-for="rule in primary.ruleHits" :key="rule.ruleId">
          <div>
            <strong>{{ rule.name ?? ruleLabel(rule.ruleId) }}</strong>
          </div>
          <p>{{ rule.reason ?? "规则原因未记录" }}</p>
          <ul v-if="rule.evidence.length">
            <li v-for="item in rule.evidence" :key="item">{{ item }}</li>
          </ul>
        </li>
      </ul>
      <p v-else class="evidence-dossier__missing">命中规则未记录</p>
    </section>

    <section>
      <header>
        <h3>当时生效的策略与数据范围</h3>
      </header>
      <dl class="evidence-dossier__facts evidence-dossier__facts--grid">
        <div>
          <dt>策略包</dt>
          <dd>{{ primary?.policy.bundleId ?? "未记录" }}</dd>
        </div>
        <div>
          <dt>版本</dt>
          <dd>{{ primary?.policy.version ?? "未记录" }}</dd>
        </div>
        <div>
          <dt>修订</dt>
          <dd>{{ primary?.policy.revision ?? "未记录" }}</dd>
        </div>
        <div>
          <dt>规范摘要</dt>
          <dd>
            <code>{{ primary?.policy.digest ?? "未记录" }}</code>
          </dd>
        </div>
        <div>
          <dt>审计记录</dt>
          <dd>{{ evidence.originalAuditCount }} 条</dd>
        </div>
        <div>
          <dt>去重后记录</dt>
          <dd>{{ evidence.logicalAuditCount }} 条</dd>
        </div>
      </dl>
      <p v-if="evidence.duplicatePolicyAuditCount" class="evidence-dossier__notice">
        已将 {{ evidence.duplicatePolicyAuditCount }}
        条重复的策略记录合并为一条判断；全部审计记录仍保留在时间线与原始证据中。
      </p>
    </section>

    <details>
      <summary>查看脱敏原始证据</summary>
      <p>敏感信息已隐藏。</p>
      <StructuredDataView :value="safeRawEvidence" />
    </details>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

import type { TraceEvidenceViewModel } from "../../types/dashboard";
import { getDecisionEvidenceLabel } from "../../data/evidence/trace-evidence";
import { redactSensitiveData } from "../../utils/data-redaction";
import {
  getResourceOperationLabel,
  getResourceSensitivityLabel,
  getResourceTypeLabel,
  getRiskAggregationLabel,
} from "../../utils/dashboard-formatters";
import { prepareEvidenceDataForDisplay, ruleLabel } from "../../utils/rule-display";
import StructuredDataView from "../common/StructuredDataView.vue";

defineOptions({ name: "EvidenceDossier" });
const props = defineProps<{ evidence: TraceEvidenceViewModel }>();
const primary = computed(() => props.evidence.primary);
const safeRawEvidence = computed(() =>
  prepareEvidenceDataForDisplay(
    redactSensitiveData(props.evidence.events.map((event) => event.raw)),
  ),
);
const riskAggregationLabel = computed(() => {
  const method = primary.value?.risk.aggregationMethod;
  return method ? getRiskAggregationLabel(method) : "未记录";
});

function resourceTypeLabel(type: string | null): string {
  return type ? getResourceTypeLabel(type) : "资源";
}

function resourceDetail(operation: string | null, sensitivity: string | null): string {
  return [
    operation ? getResourceOperationLabel(operation) : null,
    sensitivity ? getResourceSensitivityLabel(sensitivity) : null,
  ]
    .filter(Boolean)
    .join(" · ");
}
</script>

<style scoped lang="scss">
.evidence-dossier {
  display: grid;
  gap: var(--space-6);
}

.evidence-dossier > section,
.evidence-dossier > details {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  padding-top: var(--space-4);
}

.evidence-dossier > section:first-child {
  border-top: 0;
  padding-top: 0;
}

.evidence-dossier header {
  display: grid;
  gap: var(--space-1);
}

.evidence-dossier h3 {
  font-size: var(--font-size-14);
  margin: 0;
}

.evidence-dossier__facts {
  display: grid;
  margin: 0;
}

.evidence-dossier__facts--grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.evidence-dossier__facts > div {
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-2) 0;
}

.evidence-dossier__facts--grid > div:nth-child(odd) {
  padding-right: var(--space-3);
}

.evidence-dossier__facts--grid > div:nth-child(even) {
  border-left: 1px solid var(--color-border);
  padding-left: var(--space-3);
}

.evidence-dossier dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.evidence-dossier dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.evidence-dossier__structured {
  max-height: 14rem;
  overflow: auto;
}

.evidence-dossier__missing {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin: 0;
}

.resource-evidence-list,
.rule-evidence-list,
.risk-factor-list {
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}

.resource-evidence-list > li {
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-2);
  grid-template-columns: minmax(8rem, 0.45fr) minmax(0, 1fr);
  padding: var(--space-2) 0;
}

.resource-evidence-list div {
  display: grid;
}

.resource-evidence-list span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.resource-evidence-list code {
  overflow-wrap: anywhere;
}

.risk-composition {
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.risk-composition > div {
  display: grid;
  gap: var(--space-1);
  padding: var(--space-3);
}

.risk-composition > div + div {
  border-left: 1px solid var(--color-border);
}

.risk-composition span {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.risk-composition strong {
  font-size: var(--font-size-12);
  overflow-wrap: anywhere;
}

.risk-factor-list > li {
  align-items: center;
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(0, 1fr) 6.5rem;
  padding: var(--space-2) 0;
}

.risk-factor-list > li > div:first-child {
  display: grid;
  gap: var(--space-1);
}

.risk-factor-list > li > div:first-child span {
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
}

.risk-factor-list__score {
  align-items: center;
  display: grid;
  gap: var(--space-2);
  grid-template-columns: minmax(0, 1fr) 1.5rem;
}

.risk-factor-list__score::before {
  background: var(--color-surface-inset);
  content: "";
  grid-column: 1;
  grid-row: 1;
  height: 0.3rem;
}

.risk-factor-list__score > span {
  background: var(--gradient-data-danger);
  grid-column: 1;
  grid-row: 1;
  height: 0.3rem;
  transform-origin: left;
}

.risk-factor-list__score b {
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
}

.rule-evidence-list > li {
  border: 1px solid var(--color-border);
  border-left: 3px solid var(--color-danger);
  border-radius: var(--radius-1);
  display: grid;
  gap: var(--space-2);
  margin-top: var(--space-2);
  padding: var(--space-3);
}

.rule-evidence-list > li > div {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  justify-content: space-between;
}

.rule-evidence-list p {
  color: var(--color-text-muted);
  margin: 0;
}

.rule-evidence-list ul {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  margin: 0;
  padding-left: var(--space-5);
}

.evidence-dossier__notice {
  background: var(--color-warning-soft);
  border-left: 2px solid var(--color-warning);
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  margin: 0;
  padding: var(--space-2) var(--space-3);
}

.evidence-dossier > details summary {
  align-items: center;
  color: var(--color-link);
  cursor: pointer;
  display: flex;
  font-weight: var(--font-weight-semibold);
  min-height: 2.25rem;
}

.evidence-dossier > details > p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  margin: 0;
}

@media (max-width: 54rem) {
  .evidence-dossier__facts--grid,
  .risk-composition {
    grid-template-columns: 1fr;
  }

  .evidence-dossier__facts--grid > div:nth-child(even),
  .risk-composition > div + div {
    border-left: 0;
  }

  .evidence-dossier__facts--grid > div:nth-child(even) {
    padding-left: 0;
  }

  .resource-evidence-list > li {
    grid-template-columns: 1fr;
  }
}
</style>
