<template>
  <div class="loading-state" aria-live="polite" aria-busy="true" role="status">
    <span class="sr-only">正在加载数据</span>
    <span v-for="index in rows" :key="index" aria-hidden="true" class="loading-state__row"></span>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ rows?: number }>(), { rows: 5 });
</script>

<style scoped lang="scss">
.loading-state {
  display: grid;
  gap: var(--space-3);
}
.loading-state__row {
  animation: loading-pulse 1.2s ease-in-out infinite;
  background: var(--color-surface-muted);
  border-radius: var(--radius-2);
  height: 2.75rem;
}
@keyframes loading-pulse {
  50% {
    opacity: 0.48;
  }
}
@media (prefers-reduced-motion: reduce) {
  .loading-state__row {
    animation: none;
  }
}
</style>
