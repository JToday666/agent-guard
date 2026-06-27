<template>
  <header class="section-header">
    <div>
      <h2><slot /></h2>
      <p v-if="sub">{{ sub }}</p>
    </div>
    <slot name="action" />
  </header>
</template>

<script setup lang="ts">
defineOptions({ name: "SectionHeader" });
defineProps<{ sub?: string }>();
</script>

<style scoped lang="scss">
.section-header { align-items: start; display: flex; gap: var(--space-4); justify-content: space-between; flex-wrap: wrap; }
.section-header h2 { font-size: var(--font-size-16); margin: 0; }
.section-header p { color: var(--color-text-subtle); font-size: var(--font-size-12); margin: var(--space-1) 0 0; }
</style>
