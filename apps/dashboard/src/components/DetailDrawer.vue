<template>
  <aside v-if="isOpen" class="detail-drawer" aria-labelledby="detail-drawer-title" role="complementary">
    <header class="detail-drawer__header">
      <div>
        <p>{{ eyebrow }}</p>
        <h2 id="detail-drawer-title">{{ title }}</h2>
      </div>
      <button class="detail-drawer__close" type="button" aria-label="关闭详情" @click="$emit('close')">
        ×
      </button>
    </header>
    <div class="detail-drawer__body">
      <slot />
    </div>
  </aside>
</template>

<script setup lang="ts">
defineOptions({
  name: "DetailDrawer",
});

defineEmits<{
  close: [];
}>();

defineProps<{
  eyebrow: string;
  isOpen: boolean;
  title: string;
}>();
</script>

<style scoped lang="scss">
.detail-drawer {
  background: var(--color-surface);
  border-left: 1px solid var(--color-border);
  display: grid;
  grid-template-rows: auto 1fr;
  min-height: calc(100vh - var(--top-bar-height));
  min-width: 0;
}

.detail-drawer__header {
  align-items: start;
  border-bottom: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-4);
  justify-content: space-between;
  padding: var(--space-4);

  p,
  h2 {
    margin: 0;
  }

  p {
    color: var(--color-text-subtle);
    font-size: var(--font-size-12);
    font-weight: 760;
    text-transform: uppercase;
  }

  h2 {
    font-size: var(--font-size-18);
    line-height: 1.25;
    margin-top: var(--space-1);
    overflow-wrap: anywhere;
  }
}

.detail-drawer__close {
  align-items: center;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  cursor: pointer;
  display: inline-flex;
  flex: 0 0 auto;
  font-size: var(--font-size-20);
  height: 2.25rem;
  justify-content: center;
  width: 2.25rem;
}

.detail-drawer__body {
  display: grid;
  gap: var(--space-4);
  overflow: auto;
  padding: var(--space-4);
}

@media (max-width: 900px) {
  .detail-drawer {
    border-left: 0;
    bottom: 0;
    left: 0;
    min-height: 0;
    position: fixed;
    right: 0;
    top: 0;
    z-index: 50;
  }
}
</style>
