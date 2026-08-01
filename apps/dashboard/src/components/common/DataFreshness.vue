<template>
  <span class="freshness" :class="`freshness--${status}`">
    <span class="freshness__dot" aria-hidden="true"></span>
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from "vue";

import type { DataStatus } from "../../types/dashboard";

const props = defineProps<{ status: DataStatus; updatedAt?: string | null }>();

const label = computed(() => {
  if (props.status === "loading") return "正在同步";
  if (props.status === "stale") return "数据已陈旧";
  if (props.status === "error") return "连接异常";
  if (props.status === "ready" && props.updatedAt) {
    return `更新于 ${new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(props.updatedAt))}`;
  }
  return "等待数据";
});
</script>

<style scoped lang="scss">
.freshness {
  align-items: center;
  color: var(--color-text-subtle);
  display: inline-flex;
  font-size: var(--font-size-12);
  font-variant-numeric: tabular-nums;
  gap: var(--space-2);
  min-width: 8.75rem;
  white-space: nowrap;
}

.freshness__dot {
  background: var(--color-text-subtle);
  border-radius: 999px;
  height: 0.45rem;
  width: 0.45rem;
}

.freshness--ready .freshness__dot {
  background: var(--color-success);
  box-shadow: var(--glow-live);
}
.freshness--loading .freshness__dot {
  background: var(--color-active);
}
.freshness--stale .freshness__dot {
  background: var(--color-warning);
}
.freshness--error .freshness__dot {
  background: var(--color-danger);
}
</style>
