<template>
  <ol class="evidence-stage-flow" aria-label="四阶段证据流">
    <li v-for="stage in stages" :key="stage.id">
      <header>
        <span>{{ stage.eyebrow }}</span>
        <h3>{{ stage.title }}</h3>
      </header>
      <dl>
        <div
          v-for="item in stage.items"
          :key="item.id"
          :class="{ 'stage-item--missing': item.availability === 'not_recorded' }"
        >
          <dt>{{ item.label }}</dt>
          <dd>
            <button
              v-if="item.eventId"
              type="button"
              :title="item.detail ?? item.value"
              @click="emit('select-event', item.eventId)"
            >
              {{ item.value }}
            </button>
            <span v-else>{{ item.value }}</span>
            <small v-if="item.detail">{{ item.detail }}</small>
          </dd>
        </div>
      </dl>
    </li>
  </ol>
</template>

<script setup lang="ts">
import type { EvidenceStage } from "../../types/dashboard";

defineOptions({ name: "EvidenceStageFlow" });
defineProps<{ stages: EvidenceStage[] }>();
const emit = defineEmits<{ "select-event": [eventId: string] }>();
</script>

<style scoped lang="scss">
.evidence-stage-flow {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  list-style: none;
  margin: 0;
  overflow: hidden;
  padding: 0;
}

.evidence-stage-flow > li {
  display: grid;
  grid-template-rows: auto 1fr;
  min-width: 0;
  position: relative;
}

.evidence-stage-flow > li + li {
  border-left: 1px solid var(--color-border);
}

.evidence-stage-flow > li:not(:last-child)::after {
  background: var(--color-surface);
  border-right: 1px solid var(--color-active-border);
  border-top: 1px solid var(--color-active-border);
  content: "";
  height: 0.65rem;
  position: absolute;
  right: -0.36rem;
  top: 1.8rem;
  transform: rotate(45deg);
  width: 0.65rem;
  z-index: 2;
}

.evidence-stage-flow header {
  background: var(--color-surface-muted);
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  min-height: 4.25rem;
  padding: var(--space-3) var(--space-4);
}

.evidence-stage-flow header span {
  color: var(--color-active);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  letter-spacing: 0.06em;
}

.evidence-stage-flow h3 {
  font-size: var(--font-size-14);
  margin: 0;
}

.evidence-stage-flow dl {
  display: grid;
  margin: 0;
}

.evidence-stage-flow dl > div {
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-1);
  padding: var(--space-3) var(--space-4);
}

.evidence-stage-flow dl > div:last-child {
  border-bottom: 0;
}

.evidence-stage-flow dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-semibold);
}

.evidence-stage-flow dd {
  display: grid;
  gap: var(--space-1);
  margin: 0;
  min-width: 0;
}

.evidence-stage-flow button,
.evidence-stage-flow dd > span {
  background: transparent;
  border: 0;
  color: var(--color-text);
  font: inherit;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  line-height: var(--line-height-ui);
  overflow-wrap: anywhere;
  padding: 0;
  text-align: left;
}

.evidence-stage-flow button {
  color: var(--color-link);
  cursor: pointer;
}

.evidence-stage-flow button:focus-visible {
  border-radius: var(--radius-1);
  outline: 2px solid var(--color-focus);
  outline-offset: 2px;
}

.evidence-stage-flow small {
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  color: var(--color-text-muted);
  display: -webkit-box;
  font-size: var(--font-size-11);
  line-height: var(--line-height-ui);
  overflow: hidden;
}

.stage-item--missing {
  background: linear-gradient(
    135deg,
    transparent 0 48%,
    rgb(89 109 102 / 0.035) 48% 52%,
    transparent 52% 100%
  );
}

.stage-item--missing button,
.stage-item--missing dd > span {
  color: var(--color-text-subtle);
  font-weight: var(--font-weight-medium);
}

@media (max-width: 68rem) {
  .evidence-stage-flow {
    grid-template-columns: 1fr;
  }

  .evidence-stage-flow > li + li {
    border-left: 0;
    border-top: 1px solid var(--color-border);
  }

  .evidence-stage-flow > li:not(:last-child)::after {
    bottom: -0.36rem;
    left: 2rem;
    right: auto;
    top: auto;
    transform: rotate(135deg);
  }
}
</style>
