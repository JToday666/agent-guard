<template>
  <section
    class="inline-notice"
    :class="`inline-notice--${tone}`"
    :role="tone === 'danger' ? 'alert' : undefined"
  >
    <component :is="noticeIcon" class="inline-notice__icon" aria-hidden="true" :size="18" />
    <div class="inline-notice__content">
      <strong v-if="title">{{ title }}</strong>
      <div class="inline-notice__body"><slot /></div>
    </div>
    <div v-if="$slots.action" class="inline-notice__action"><slot name="action" /></div>
  </section>
</template>

<script setup lang="ts">
import { CircleAlert, CircleCheck, Info, ShieldCheck, TriangleAlert } from "@lucide/vue";
import { computed } from "vue";

defineOptions({ name: "InlineNotice" });

const props = withDefaults(
  defineProps<{
    title?: string;
    tone?: "neutral" | "success" | "warning" | "danger" | "protective";
  }>(),
  {
    title: "",
    tone: "neutral",
  },
);

const noticeIcon = computed(() => {
  if (props.tone === "success") return CircleCheck;
  if (props.tone === "warning") return TriangleAlert;
  if (props.tone === "danger") return CircleAlert;
  if (props.tone === "protective") return ShieldCheck;
  return Info;
});
</script>

<style scoped lang="scss">
.inline-notice {
  align-items: start;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border);
  border-left: 3px solid var(--color-border-strong);
  color: var(--color-text-muted);
  display: grid;
  font-size: var(--font-size-13);
  gap: var(--space-3);
  grid-template-columns: auto minmax(0, 1fr) auto;
  padding: var(--space-3) var(--space-4);
}

.inline-notice__icon {
  color: var(--color-text-subtle);
  margin-top: 0.1rem;
}

.inline-notice__content {
  min-width: 0;
}

.inline-notice__content strong {
  color: var(--color-text);
  display: block;
  font-weight: var(--font-weight-semibold);
  margin-bottom: var(--space-1);
}

.inline-notice__body {
  overflow-wrap: anywhere;
}

.inline-notice__body :deep(p) {
  margin: 0;
}

.inline-notice__action {
  align-self: center;
}

.inline-notice__action :deep(button),
.inline-notice__action :deep(a) {
  background: var(--color-surface);
  border: 1px solid currentColor;
  border-radius: var(--radius-2);
  color: inherit;
  display: inline-flex;
  font-weight: var(--font-weight-semibold);
  min-height: 2.25rem;
  padding: 0 var(--space-3);
  text-decoration: none;
}

.inline-notice--success {
  background: var(--color-success-soft);
  border-color: var(--color-success-border);
  border-left-color: var(--color-success);

  .inline-notice__icon {
    color: var(--color-success);
  }
}

.inline-notice--warning {
  background: var(--color-warning-soft);
  border-color: var(--color-warning-border);
  border-left-color: var(--color-warning);

  .inline-notice__icon {
    color: var(--color-warning);
  }
}

.inline-notice--danger {
  background: var(--color-danger-soft);
  border-color: var(--color-danger-border);
  border-left-color: var(--color-danger);

  .inline-notice__icon {
    color: var(--color-danger);
  }
}

.inline-notice--protective {
  background: var(--color-active-soft);
  border-color: var(--color-active-border);
  border-left-color: var(--color-active);

  .inline-notice__icon {
    color: var(--color-active);
  }
}
</style>
