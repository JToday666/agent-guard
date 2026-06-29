<template>
  <span class="status-badge" :class="`status-badge--${tone}`">
    <span class="status-badge__dot" aria-hidden="true"></span>
    <span class="status-badge__text">{{ label }}</span>
  </span>
</template>

<script setup lang="ts">
defineOptions({
  name: "StatusBadge",
});

defineProps<{
  label: string;
  tone: "neutral" | "success" | "warning" | "danger";
}>();
</script>

<style scoped lang="scss">
.status-badge {
  align-items: center;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-pill);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-2);
  line-height: var(--line-height-ui);
  min-height: 1.75rem;
  max-width: 100%;
  padding: 0 var(--space-3);
  white-space: nowrap;
}

.status-badge__dot {
  border-radius: 999px;
  flex: 0 0 auto;
  height: 0.5rem;
  width: 0.5rem;
}

.status-badge__text {
  overflow: hidden;
  text-overflow: ellipsis;
}

.status-badge--neutral {
  background: var(--color-surface-muted);
  color: var(--color-text-muted);

  .status-badge__dot {
    background: var(--color-text-muted);
  }
}

.status-badge--success {
  background: var(--color-success-soft);
  border-color: var(--color-success-border);
  color: var(--color-success);

  .status-badge__dot {
    background: var(--color-success);
  }
}

.status-badge--warning {
  background: var(--color-warning-soft);
  border-color: var(--color-warning-border);
  color: var(--color-warning);

  .status-badge__dot {
    background: var(--color-warning);
  }
}

.status-badge--danger {
  background: var(--color-danger-soft);
  border-color: var(--color-danger-border);
  color: var(--color-danger);

  .status-badge__dot {
    background: var(--color-danger);
  }
}
</style>
