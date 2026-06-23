<template>
  <aside
    v-if="isOpen"
    ref="drawerElement"
    aria-labelledby="detail-drawer-title"
    :aria-modal="isMobile"
    class="detail-drawer"
    role="dialog"
    tabindex="-1"
    @keydown.esc.prevent="emit('close')"
    @keydown.tab="handleTabKey"
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
</template>

<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref, watch } from "vue";
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
const drawerElement = ref<HTMLElement | null>(null);
const isMobile = ref(false);
let restoreFocusElement: HTMLElement | null = null;
let mobileQuery: MediaQueryList | null = null;

function syncMobileState(event: MediaQueryList | MediaQueryListEvent): void {
  isMobile.value = event.matches;
}

function handleTabKey(event: KeyboardEvent): void {
  if (!isMobile.value || !drawerElement.value) return;
  const focusableElements = [...drawerElement.value.querySelectorAll<HTMLElement>(
    'a[href], button:not([disabled]), summary, input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )];
  const firstElement = focusableElements[0];
  const lastElement = focusableElements.at(-1);
  if (!firstElement || !lastElement) return;
  if (event.shiftKey && document.activeElement === firstElement) {
    event.preventDefault();
    lastElement.focus();
  } else if (!event.shiftKey && document.activeElement === lastElement) {
    event.preventDefault();
    firstElement.focus();
  }
}

onMounted(() => {
  mobileQuery = window.matchMedia("(max-width: 900px)");
  syncMobileState(mobileQuery);
  mobileQuery.addEventListener("change", syncMobileState);
});

onUnmounted(() => mobileQuery?.removeEventListener("change", syncMobileState));

watch(
  () => props.isOpen,
  async (isOpen, wasOpen) => {
    if (isOpen) {
      restoreFocusElement =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      await nextTick();
      closeButtonElement.value?.focus();
      return;
    }

    if (wasOpen) {
      await nextTick();
      restoreFocusElement?.focus();
      restoreFocusElement = null;
    }
  },
);
</script>

<style scoped lang="scss">
.detail-drawer {
  background: var(--color-surface);
  border-left: 1px solid var(--color-border);
  box-shadow: var(--shadow-raised);
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
