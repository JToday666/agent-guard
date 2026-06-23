<template>
  <dl class="metric-strip">
    <div v-for="item in items" :key="item.label" :class="`metric-strip__item metric-strip__item--${item.tone ?? 'neutral'}`">
      <dt>{{ item.label }}</dt>
      <dd>
        <RouterLink v-if="item.route" :to="item.route">{{ item.value }}</RouterLink>
        <span v-else>{{ item.value }}</span>
      </dd>
      <small>{{ item.detail }}</small>
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
    tone?: "neutral" | "success" | "warning" | "danger";
    value: string;
  }>;
}>();
</script>

<style scoped lang="scss">
.metric-strip {
  background: rgb(255 255 255 / 0.62);
  border-block: 1px solid var(--color-border);
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr));
  margin: 0;
}

.metric-strip__item {
  min-width: 0;
  padding: var(--space-4);
  position: relative;
}

.metric-strip__item:not(:last-child)::after {
  background: var(--color-border);
  content: "";
  inset-block: var(--space-4);
  position: absolute;
  right: 0;
  width: 1px;
}

dt,
small {
  color: var(--color-text-subtle);
  display: block;
  font-size: var(--font-size-12);
}

dd {
  font-size: clamp(1.35rem, 2.2vw, 1.875rem);
  font-weight: var(--font-weight-bold);
  line-height: 1.15;
  margin: var(--space-2) 0 var(--space-1);
}

dd a,
dd span { color: inherit; text-decoration: none; }
dd a:hover { color: var(--color-active); }
.metric-strip__item--success dd { color: var(--color-success); }
.metric-strip__item--warning dd { color: var(--color-warning); }
.metric-strip__item--danger dd { color: var(--color-danger); }

@media (max-width: 640px) {
  .metric-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metric-strip__item:nth-child(2n)::after { display: none; }
  .metric-strip__item { border-bottom: 1px solid var(--color-border); }
}
</style>
