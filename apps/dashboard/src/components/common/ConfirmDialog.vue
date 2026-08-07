<template>
  <dialog
    ref="dialogElement"
    class="confirm-dialog"
    :class="{ 'confirm-dialog--closing': isClosing }"
    :aria-busy="isSubmitting"
    :aria-describedby="descriptionId"
    :aria-labelledby="titleId"
    @cancel="handleCancel"
    @click.self="handleBackdropClick"
  >
    <div class="confirm-dialog__surface" @animationend="handleSurfaceAnimationEnd">
      <header>
        <span
          class="confirm-dialog__signal"
          :class="`confirm-dialog__signal--${tone}`"
          aria-hidden="true"
        ></span>
        <div>
          <p>{{ eyebrow }}</p>
          <h2 :id="titleId">{{ title }}</h2>
        </div>
      </header>

      <div :id="descriptionId" class="confirm-dialog__body">
        <slot></slot>
      </div>

      <p v-if="errorMessage" class="confirm-dialog__error" role="alert">
        {{ errorMessage }}
      </p>

      <footer>
        <button
          ref="cancelButtonElement"
          type="button"
          :disabled="isSubmitting"
          @click="requestClose"
        >
          {{ cancelLabel }}
        </button>
        <button
          type="button"
          class="confirm-dialog__confirm"
          :class="`confirm-dialog__confirm--${tone}`"
          :disabled="confirmDisabled || isSubmitting"
          @click="emit('confirm')"
        >
          {{ isSubmitting ? busyLabel : confirmLabel }}
        </button>
      </footer>
    </div>
  </dialog>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, onDeactivated, onMounted, ref, useId } from "vue";

defineOptions({ name: "ConfirmDialog" });

const props = withDefaults(
  defineProps<{
    busyLabel?: string;
    cancelLabel?: string;
    confirmDisabled?: boolean;
    confirmLabel: string;
    errorMessage?: string;
    eyebrow?: string;
    isSubmitting?: boolean;
    title: string;
    tone?: "primary" | "warning" | "danger";
  }>(),
  {
    busyLabel: "提交中…",
    cancelLabel: "取消",
    confirmDisabled: false,
    errorMessage: "",
    eyebrow: "确认操作",
    isSubmitting: false,
    tone: "primary",
  },
);

const emit = defineEmits<{
  close: [];
  confirm: [];
}>();

const cancelButtonElement = ref<HTMLButtonElement | null>(null);
const dialogElement = ref<HTMLDialogElement | null>(null);
const isClosing = ref(false);
const id = useId();
const descriptionId = `confirm-dialog-description-${id}`;
const titleId = `confirm-dialog-title-${id}`;
let restoreFocusElement: HTMLElement | null = null;
let closeFallbackTimer: number | null = null;

onMounted(async () => {
  restoreFocusElement =
    document.activeElement instanceof HTMLElement ? document.activeElement : null;
  await nextTick();
  dialogElement.value?.showModal();
  cancelButtonElement.value?.focus();
});

onBeforeUnmount(() => {
  clearCloseFallback();
  if (dialogElement.value?.open) dialogElement.value.close();
  restoreFocusElement?.focus();
});

onDeactivated(() => {
  if (!dialogElement.value?.open) return;
  clearCloseFallback();
  dialogElement.value.close();
  emit("close");
});

function requestClose(): void {
  if (props.isSubmitting || isClosing.value) return;
  isClosing.value = true;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    finalizeClose();
    return;
  }
  closeFallbackTimer = window.setTimeout(finalizeClose, 180);
}

function finalizeClose(): void {
  if (!isClosing.value) return;
  clearCloseFallback();
  isClosing.value = false;
  dialogElement.value?.close();
  emit("close");
}

function clearCloseFallback(): void {
  if (closeFallbackTimer !== null) window.clearTimeout(closeFallbackTimer);
  closeFallbackTimer = null;
}

function handleSurfaceAnimationEnd(): void {
  if (isClosing.value) finalizeClose();
}

function handleCancel(event: Event): void {
  event.preventDefault();
  requestClose();
}

function handleBackdropClick(): void {
  requestClose();
}
</script>

<style scoped lang="scss">
.confirm-dialog {
  background: transparent;
  border: 0;
  color: var(--color-text);
  max-height: calc(100vh - 2 * var(--space-7));
  max-width: min(32rem, calc(100vw - 2 * var(--space-7)));
  overflow: visible;
  padding: 0;
  width: 100%;

  &::backdrop {
    background: color-mix(in srgb, var(--color-shell-strong) 48%, transparent);
    backdrop-filter: blur(3px);
  }
}

.confirm-dialog__surface {
  animation: confirm-dialog-enter var(--transition-panel) both;
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-3);
  box-shadow: var(--shadow-raised);
  display: grid;
  gap: var(--space-5);
  max-height: calc(100vh - 2 * var(--space-7));
  overflow-y: auto;
  overscroll-behavior: contain;
  padding: var(--space-6);
}

.confirm-dialog[open]::backdrop {
  animation: confirm-dialog-backdrop-enter var(--transition-panel) both;
}

.confirm-dialog--closing .confirm-dialog__surface {
  animation: confirm-dialog-leave var(--transition-instant) both;
}

.confirm-dialog--closing::backdrop {
  animation: confirm-dialog-backdrop-leave var(--transition-instant) both;
}

.confirm-dialog header {
  align-items: start;
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 0.25rem minmax(0, 1fr);
}

.confirm-dialog__signal {
  background: var(--color-active);
  border-radius: var(--radius-pill);
  height: 100%;
  min-height: 2.75rem;
}
.confirm-dialog__signal--warning {
  background: var(--color-warning);
}
.confirm-dialog__signal--danger {
  background: var(--color-danger);
}

.confirm-dialog header p,
.confirm-dialog h2 {
  margin: 0;
}

.confirm-dialog header p {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
}

.confirm-dialog h2 {
  font-size: var(--font-size-20);
  margin-top: var(--space-1);
  text-wrap: balance;
}

.confirm-dialog__body {
  color: var(--color-text-muted);
  display: grid;
  gap: var(--space-3);
}

.confirm-dialog__error {
  background: var(--color-danger-soft);
  border-left: 3px solid var(--color-danger);
  color: var(--color-danger);
  margin: 0;
  padding: var(--space-3);
}

.confirm-dialog footer {
  border-top: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-3);
  justify-content: flex-end;
  padding-top: var(--space-4);
}

.confirm-dialog button {
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-2);
  color: var(--color-text);
  cursor: pointer;
  min-height: 2.75rem;
  padding: 0 var(--space-4);
}

.confirm-dialog button:hover:not(:disabled) {
  background: var(--color-row-hover);
  border-color: var(--color-active-border);
}

.confirm-dialog button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.confirm-dialog__confirm {
  color: var(--color-active-text) !important;
  font-weight: var(--font-weight-bold);
}

.confirm-dialog__confirm--primary {
  background: var(--color-active) !important;
  border-color: var(--color-active) !important;
}

.confirm-dialog__confirm--warning {
  background: var(--color-warning) !important;
  border-color: var(--color-warning) !important;
}

.confirm-dialog__confirm--danger {
  background: var(--color-danger) !important;
  border-color: var(--color-danger) !important;
}

@keyframes confirm-dialog-enter {
  from {
    opacity: 0;
    transform: translateY(0.5rem) scale(0.985);
  }

  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@keyframes confirm-dialog-leave {
  from {
    opacity: 1;
    transform: translateY(0) scale(1);
  }

  to {
    opacity: 0;
    transform: translateY(0.25rem) scale(0.99);
  }
}

@keyframes confirm-dialog-backdrop-enter {
  from {
    opacity: 0;
  }

  to {
    opacity: 1;
  }
}

@keyframes confirm-dialog-backdrop-leave {
  from {
    opacity: 1;
  }

  to {
    opacity: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .confirm-dialog__surface,
  .confirm-dialog[open]::backdrop,
  .confirm-dialog--closing .confirm-dialog__surface,
  .confirm-dialog--closing::backdrop {
    animation: none;
  }
}
</style>
