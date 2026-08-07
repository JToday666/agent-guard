<template>
  <dl class="metric-strip">
    <div
      v-for="item in items"
      :key="item.label"
      :class="[
        `metric-strip__item--${item.tone ?? 'neutral'}`,
        { 'metric-strip__item--interactive': item.route },
      ]"
      class="metric-strip__item"
    >
      <dt>{{ item.label }}</dt>
      <dd>
        <RouterLink
          v-if="item.route"
          :aria-label="`${item.label}：${item.value}。${item.detail}`"
          :to="item.route"
          >{{ item.value }}</RouterLink
        >
        <span v-else>{{ item.value }}</span>
      </dd>
      <small>{{ item.detail }}</small>
      <span class="metric-strip__bar" aria-hidden="true"></span>
    </div>
  </dl>
</template>

<script setup lang="ts">
defineOptions({ name: "MetricStrip" });
defineProps<{
  items: Array<{
    detail: string;
    label: string;
    route?: string;
    tone?: "neutral" | "protective" | "success" | "warning" | "danger";
    value: string;
  }>;
}>();
</script>

<style scoped lang="scss">
.metric-strip {
  background: color-mix(in srgb, var(--color-surface) 72%, transparent);
  border-block: 1px solid var(--color-border);
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr));
  margin: 0;
}

.metric-strip__item {
  min-width: 0;
  padding: var(--space-4);
  position: relative;

  &:not(:last-child)::after {
    background: var(--color-border);
    content: "";
    inset-block: var(--space-4);
    position: absolute;
    right: 0;
    width: 1px;
  }

  &--interactive:has(dd a:hover) {
    background: var(--color-row-hover);
  }

  &--interactive:has(dd a:focus-visible) {
    outline: 2px solid var(--color-focus);
    outline-offset: 2px;
  }
}

.metric-strip__bar {
  background: var(--color-border);
  bottom: 0;
  height: 3px;
  left: 0;
  position: absolute;
  right: 0;
  transition: opacity var(--transition-fast);
}

dt,
small {
  color: var(--color-text-subtle);
  display: block;
  font-size: var(--font-size-12);
}

dd {
  font-size: clamp(1.35rem, 2.2vw, 1.875rem);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-bold);
  line-height: 1.15;
  margin: var(--space-2) 0 var(--space-1);
}

dd a,
dd span {
  color: inherit;
  text-decoration: none;
}

dd a::after {
  content: "";
  inset: 0;
  position: absolute;
}

dd a:hover {
  color: var(--color-active);
}

.metric-strip__item--success {
  dd {
    color: var(--color-success);
  }
  .metric-strip__bar {
    background: var(--gradient-data-active);
    opacity: 0.6;
  }
}
.metric-strip__item--protective {
  dd {
    color: var(--color-active);
  }
  .metric-strip__bar {
    background: var(--gradient-data-active);
    opacity: 0.7;
  }
}
.metric-strip__item--warning {
  dd {
    color: var(--color-warning);
  }
  .metric-strip__bar {
    background: var(--gradient-data-warning);
    opacity: 0.7;
  }
}
.metric-strip__item--danger {
  dd {
    color: var(--color-danger);
  }
  .metric-strip__bar {
    background: var(--gradient-data-danger);
    opacity: 0.7;
  }
}
.metric-strip__item--neutral .metric-strip__bar {
  opacity: 0;
}
</style>
