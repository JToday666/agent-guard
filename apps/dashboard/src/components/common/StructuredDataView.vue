<template>
  <section class="structured-data" :aria-labelledby="titleId">
    <header>
      <h3 :id="titleId">结构化原始数据</h3>
      <button type="button" @click="handleCopy">{{ copyLabel }}</button>
    </header>
    <dl v-if="entries.length" class="structured-data__summary">
      <div v-for="entry in entries" :key="entry.key">
        <dt>{{ entry.key }}</dt>
        <dd>{{ entry.value }}</dd>
      </div>
    </dl>
    <details>
      <summary>查看完整 JSON</summary>
      <pre>{{ serializedValue }}</pre>
    </details>
  </section>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, useId } from "vue";

import { redactSensitiveData } from "../../utils/data-redaction";
import { serializeStructuredData } from "../../utils/structured-data";

defineOptions({ name: "StructuredDataView" });
const props = defineProps<{ value: unknown }>();
const titleId = useId();
const copyLabel = ref("复制 JSON");
let resetCopyTimer: number | undefined;
const safeValue = computed(() => redactSensitiveData(props.value));
const serializedValue = computed(() => serializeStructuredData(safeValue.value));
const entries = computed(() => {
  if (!safeValue.value || typeof safeValue.value !== "object" || Array.isArray(safeValue.value))
    return [];
  return Object.entries(safeValue.value as Record<string, unknown>)
    .slice(0, 8)
    .map(([key, value]) => ({
      key,
      value:
        typeof value === "object" && value !== null
          ? Array.isArray(value)
            ? `${value.length} 项`
            : `${Object.keys(value).length} 个字段`
          : String(value ?? "null"),
    }));
});

async function handleCopy(): Promise<void> {
  window.clearTimeout(resetCopyTimer);
  try {
    await navigator.clipboard.writeText(serializedValue.value);
    copyLabel.value = "已复制";
  } catch {
    copyLabel.value = "复制失败";
  }
  resetCopyTimer = window.setTimeout(() => {
    copyLabel.value = "复制 JSON";
  }, 1600);
}
onUnmounted(() => {
  window.clearTimeout(resetCopyTimer);
});
</script>

<style scoped lang="scss">
.structured-data {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  padding-top: var(--space-4);
}
.structured-data header {
  align-items: center;
  display: flex;
  justify-content: space-between;
}
.structured-data h3 {
  font-size: var(--font-size-14);
  margin: 0;
}
.structured-data button {
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  font-size: var(--font-size-12);
  padding: 0 var(--space-3);
  &:hover {
    background: var(--color-surface-muted);
    border-color: var(--color-active);
  }
}
.structured-data__summary {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: 1px;
  margin: 0;
  overflow: hidden;
}
.structured-data__summary > div {
  background: var(--color-surface-muted);
  display: grid;
  gap: var(--space-3);
  grid-template-columns: minmax(6rem, 0.45fr) minmax(0, 1fr);
  padding: var(--space-2) var(--space-3);
}
.structured-data dt {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  letter-spacing: 0.04em;
  overflow-wrap: anywhere;
  text-transform: uppercase;
}
.structured-data dd {
  color: var(--color-text);
  font-size: var(--font-size-12);
  margin: 0;
  overflow-wrap: anywhere;
}
.structured-data summary {
  align-items: center;
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  display: inline-flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  list-style: none;
  min-height: 2.25rem;
  padding: 0 var(--space-3);
  &:hover {
    background: var(--color-surface-muted);
    border-color: var(--color-active);
  }
  &::marker,
  &::-webkit-details-marker {
    display: none;
  }
}
.structured-data pre {
  background: var(--color-surface-inset);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-12);
  line-height: 1.65;
  margin: var(--space-3) 0 0;
  max-height: 22rem;
  overflow: auto;
  padding: var(--space-4);
  tab-size: 2;
  white-space: pre-wrap;
}
</style>
