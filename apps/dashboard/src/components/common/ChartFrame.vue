<template>
  <section class="chart-frame" :aria-labelledby="titleId">
    <header class="chart-frame__header">
      <div>
        <h2 :id="titleId">{{ title }}</h2>
        <p v-if="description">{{ description }}</p>
      </div>
      <div class="chart-frame__context">
        <span v-if="rangeLabel">{{ rangeLabel }}</span>
        <slot name="controls" />
      </div>
    </header>
    <div class="chart-frame__plot">
      <slot />
    </div>
    <p v-if="summary" class="sr-only">{{ summary }}</p>
    <footer v-if="$slots.footer" class="chart-frame__footer">
      <slot name="footer" />
    </footer>
  </section>
</template>

<script setup lang="ts">
import { useId } from "vue";

defineOptions({ name: "ChartFrame" });

defineProps<{
  description?: string;
  rangeLabel?: string;
  summary?: string;
  title: string;
}>();

const titleId = `chart-frame-title-${useId()}`;
</script>

<style scoped lang="scss">
.chart-frame {
  display: grid;
  gap: var(--space-4);
  min-width: 0;
}

.chart-frame__header {
  align-items: start;
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
}

.chart-frame__header h2,
.chart-frame__header p {
  margin: 0;
}

.chart-frame__header h2 {
  font-size: var(--font-size-18);
  letter-spacing: -0.015em;
  line-height: var(--line-height-tight);
}

.chart-frame__header p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin-top: var(--space-1);
}

.chart-frame__context {
  align-items: center;
  color: var(--color-text-subtle);
  display: flex;
  flex: 0 0 auto;
  font-size: var(--font-size-11);
  gap: var(--space-2);
}

.chart-frame__plot {
  background: var(--gradient-chart-surface), var(--color-surface-muted);
  border: 1px solid var(--color-border);
  min-height: 12rem;
  min-width: 0;
  overflow: hidden;
  padding: var(--space-4);
  position: relative;
}

.chart-frame__footer {
  border-top: 1px solid var(--color-border);
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  padding-top: var(--space-3);
}
</style>
