<template>
  <section class="empty-state" :aria-label="title">
    <h2>{{ title }}</h2>
    <p>{{ message }}</p>
    <slot />
  </section>
</template>

<script setup lang="ts">
defineOptions({
  name: "EmptyState",
});

defineProps<{
  message: string;
  title: string;
}>();
</script>

<style scoped lang="scss">
.empty-state {
  background: var(--color-surface);
  border: 1px dashed var(--color-border-strong);
  border-radius: var(--radius-3);
  display: grid;
  gap: var(--space-2);
  min-height: 8rem;
  padding: var(--space-5);
  place-content: center;
  text-align: center;

  h2,
  p {
    margin: 0;
  }

  h2 {
    font-size: var(--font-size-18);
  }

  p {
    color: var(--color-text-muted);
    max-width: 36rem;
  }
}
</style>
