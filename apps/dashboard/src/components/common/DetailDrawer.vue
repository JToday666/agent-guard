<template>
  <Transition name="detail-drawer" @after-leave="handleAfterLeave">
    <aside
      v-if="isOpen"
      aria-labelledby="detail-drawer-title"
      class="detail-drawer"
      role="dialog"
      tabindex="-1"
      @keydown.esc.prevent="emit('close')"
    >
      <header class="detail-drawer__header">
        <div>
          <p>{{ eyebrow }}</p>
          <h2 id="detail-drawer-title">{{ title }}</h2>
        </div>
        <button
          ref="closeButtonElement"
          class="detail-drawer__close"
          type="button"
          aria-label="关闭详情"
          @click="emit('close')"
        >
          <X aria-hidden="true" :size="18" />
        </button>
      </header>
      <div class="detail-drawer__body">
        <slot />
      </div>
    </aside>
  </Transition>
</template>

<script setup lang="ts">
import { nextTick, ref, watch } from "vue";
import { X } from "@lucide/vue";

defineOptions({
  name: "DetailDrawer",
});

const emit = defineEmits<{
  close: [];
}>();

const props = defineProps<{
  eyebrow: string;
  isOpen: boolean;
  title: string;
}>();

const closeButtonElement = ref<HTMLButtonElement | null>(null);
let restoreFocusElement: HTMLElement | null = null;

watch(
  () => props.isOpen,
  async (isOpen) => {
    if (!isOpen) return;
    restoreFocusElement =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    await nextTick();
    closeButtonElement.value?.focus();
  },
);

function handleAfterLeave(): void {
  restoreFocusElement?.focus();
  restoreFocusElement = null;
}
</script>

<style scoped lang="scss">
.detail-drawer {
  background: var(--color-surface);
  border-left: 1px solid var(--color-border);
  box-shadow: var(--shadow-raised);
  display: grid;
  grid-template-rows: auto 1fr;
  inset: var(--top-bar-height) 0 0 auto;
  min-width: 0;
  overscroll-behavior: contain;
  position: fixed;
  transform-origin: right center;
  width: clamp(22rem, 30vw, 27rem);
  z-index: 45;
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
    font-weight: var(--font-weight-bold);
    text-transform: uppercase;
  }

  h2 {
    font-size: var(--font-size-18);
    font-weight: var(--font-weight-bold);
    line-height: var(--line-height-tight);
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

  &:hover {
    background: var(--color-danger-soft);
    border-color: var(--color-danger-border);
    color: var(--color-danger);
  }
}

.detail-drawer__body {
  align-content: start;
  display: grid;
  gap: var(--space-5);
  grid-auto-rows: max-content;
  overflow: auto;
  overscroll-behavior: contain;
  padding: var(--space-5) var(--space-5) var(--space-7);
}

.detail-drawer-enter-active,
.detail-drawer-leave-active {
  transition:
    opacity var(--transition-panel),
    transform var(--transition-panel);
}

.detail-drawer-enter-from,
.detail-drawer-leave-to {
  opacity: 0;
  transform: translateX(1rem);
}

@media (prefers-reduced-motion: reduce) {
  .detail-drawer-enter-active,
  .detail-drawer-leave-active {
    transition: none;
  }

  .detail-drawer-enter-from,
  .detail-drawer-leave-to {
    opacity: 1;
    transform: none;
  }
}
</style>
