<template>
  <dl class="detail-grid">
    <div v-for="item in items" :key="item.label" class="detail-grid__cell">
      <dt>{{ item.label }}</dt>
      <dd>{{ item.value }}</dd>
    </div>
  </dl>
</template>

<script setup lang="ts">
defineOptions({ name: "DetailGrid" });
defineProps<{ items: Array<{ label: string; value: string | number }> }>();
</script>

<style scoped lang="scss">
.detail-grid { display: grid; gap: 1px; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); margin: 0; overflow: hidden; }
.detail-grid__cell { background: var(--color-surface-muted); display: grid; gap: var(--space-1); padding: var(--space-3); }
.detail-grid__cell dt { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.detail-grid__cell dd { margin: 0; overflow-wrap: anywhere; }
</style>
