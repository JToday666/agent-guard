<template>
  <dl class="evidence-facts" aria-label="证据事实摘要">
    <div
      v-for="fact in facts"
      :key="fact.id"
      class="evidence-facts__item"
      :class="[
        `evidence-facts__item--${fact.tone}`,
        { 'evidence-facts__item--missing': fact.availability === 'not_recorded' },
      ]"
    >
      <dt>
        <component :is="factIcon(fact.id)" :size="15" stroke-width="1.8" aria-hidden="true" />
        {{ fact.label }}
      </dt>
      <dd>
        <strong>{{ fact.value }}</strong>
        <span>{{ fact.detail }}</span>
      </dd>
    </div>
  </dl>
</template>

<script setup lang="ts">
import {
  Activity,
  FileCheck2,
  Fingerprint,
  GitPullRequestArrow,
  ShieldCheck,
  Sparkles,
} from "@lucide/vue";
import type { Component } from "vue";

import type { EvidenceFact } from "../../types/dashboard";

defineOptions({ name: "EvidenceFactStrip" });
defineProps<{ facts: EvidenceFact[] }>();

const icons: Record<EvidenceFact["id"], Component> = {
  audit_integrity: Fingerprint,
  decision: ShieldCheck,
  execution: Activity,
  intervention: GitPullRequestArrow,
  result_disposition: Sparkles,
  side_effects: FileCheck2,
};

function factIcon(id: EvidenceFact["id"]): Component {
  return icons[id];
}
</script>

<style scoped lang="scss">
.evidence-facts {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  margin: 0;
  overflow: hidden;
}

.evidence-facts__item {
  border-left: 3px solid var(--color-border-strong);
  display: grid;
  gap: var(--space-2);
  min-width: 0;
  padding: var(--space-3);
}

.evidence-facts__item + .evidence-facts__item {
  border-inline-start-width: 1px;
}

.evidence-facts__item--protective {
  border-top: 3px solid var(--color-active);
}

.evidence-facts__item--success {
  border-top: 3px solid var(--color-success);
}

.evidence-facts__item--warning {
  border-top: 3px solid var(--color-warning);
}

.evidence-facts__item--danger {
  border-top: 3px solid var(--color-danger);
}

.evidence-facts__item--missing {
  background: var(--color-surface-muted);
}

.evidence-facts dt {
  align-items: center;
  color: var(--color-text-subtle);
  display: flex;
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  gap: var(--space-2);
  letter-spacing: 0.03em;
}

.evidence-facts dd {
  display: grid;
  gap: var(--space-1);
  margin: 0;
  min-width: 0;
}

.evidence-facts strong {
  color: var(--color-text);
  font-size: var(--font-size-16);
  line-height: var(--line-height-tight);
  overflow-wrap: anywhere;
}

.evidence-facts span {
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
  color: var(--color-text-muted);
  display: -webkit-box;
  font-size: var(--font-size-11);
  line-height: var(--line-height-ui);
  overflow: hidden;
}

@media (max-width: 90rem) {
  .evidence-facts {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .evidence-facts__item:nth-child(n + 4) {
    border-top: 1px solid var(--color-border);
  }
}

@media (max-width: 54rem) {
  .evidence-facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .evidence-facts__item:nth-child(n + 3) {
    border-top: 1px solid var(--color-border);
  }
}
</style>
