<template>
  <section class="error-state" role="alert">
    <div>
      <strong>{{ title }}</strong>
      <p>{{ message }}</p>
    </div>
    <button type="button" :aria-busy="isRetrying" :disabled="isRetrying" @click="emit('retry')">
      重新加载
    </button>
  </section>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ isRetrying?: boolean; message: string; title?: string }>(), {
  isRetrying: false,
  title: "数据连接异常",
});
const emit = defineEmits<{ retry: [] }>();
</script>

<style scoped lang="scss">
.error-state {
  align-items: center;
  background: var(--color-danger-soft);
  border: 1px solid var(--color-danger-border);
  border-radius: var(--radius-2);
  color: var(--color-danger);
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
  padding: var(--space-4);
}
.error-state p {
  color: var(--color-text-muted);
  margin: var(--space-1) 0 0;
}
.error-state button {
  background: var(--color-surface);
  border: 1px solid var(--color-danger-border);
  border-radius: var(--radius-2);
  color: var(--color-danger);
  cursor: pointer;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
}
.error-state button:disabled {
  cursor: wait;
  opacity: 0.65;
}
</style>
