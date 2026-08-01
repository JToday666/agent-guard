<template>
  <div class="loading-state" aria-live="polite" aria-busy="true">
    <span v-for="index in rows" :key="index"></span>
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
.loading-state span {
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
  .loading-state span {
    animation: none;
  }
}
</style>
