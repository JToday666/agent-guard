<template>
  <RouterLink class="metric-card" :class="`metric-card--${tone}`" :to="route">
    <span>{{ label }}</span>
    <strong>{{ value }}</strong>
  </RouterLink>
</template>

<script setup lang="ts">
defineOptions({
  name: "MetricCard",
});

defineProps<{
  label: string;
  route: string;
  tone: "neutral" | "warning" | "danger" | "success";
  value: string;
}>();
</script>

<style scoped lang="scss">
.metric-card {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-3);
  box-shadow: var(--shadow-subtle);
  color: var(--color-text);
  display: grid;
  gap: var(--space-3);
  min-height: 7rem;
  min-width: 0;
  padding: var(--space-4);
  text-decoration: none;

  &:hover {
    border-color: var(--color-active-border);
    box-shadow: var(--shadow-raised);
    transform: translateY(-1px);
  }

  span {
    color: var(--color-text-muted);
    font-size: var(--font-size-13);
    font-weight: var(--font-weight-semibold);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  strong {
    font-size: var(--font-size-28);
    line-height: var(--line-height-tight);
  }
}

.metric-card--danger {
  border-color: var(--color-danger-border);
}

.metric-card--warning {
  border-color: var(--color-warning-border);
}

.metric-card--success {
  border-color: var(--color-success-border);
}
</style>
