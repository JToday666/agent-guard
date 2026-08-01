<template>
  <div v-if="items.length" class="distribution" aria-label="攻击类型分布" role="img">
    <div v-for="item in items" :key="item.label" class="distribution__row">
      <div>
        <span>{{ getAttackTypeLabel(item.label) }}</span
        ><strong>{{ item.value }} · {{ getPercent(item.value) }}</strong>
      </div>
      <span class="distribution__track"
        ><i :style="{ transform: `scaleX(${item.value / maxValue})` }"></i
      ></span>
    </div>
  </div>
  <p v-else class="chart-empty">暂无攻击类型数据</p>
</template>

<script setup lang="ts">
import { computed } from "vue";
const props = defineProps<{ items: Array<{ label: string; value: number }> }>();
const maxValue = computed(() => Math.max(1, ...props.items.map((item) => item.value)));
const totalValue = computed(() => props.items.reduce((total, item) => total + item.value, 0));
function getPercent(value: number) {
  return totalValue.value ? `${((value / totalValue.value) * 100).toFixed(0)}%` : "0%";
}
function getAttackTypeLabel(value: string) {
  return (
    (
      {
        prompt_injection: "提示注入",
        indirect_prompt_injection: "间接提示注入",
        tool_hijacking: "工具调用劫持",
        memory_poisoning: "记忆中毒",
        sensitive_file_access: "敏感文件访问",
        code_execution_abuse: "危险代码执行",
        benign: "正常样本",
        unknown: "未分类",
      } as Record<string, string>
    )[value] ?? value
  );
}
</script>

<style scoped lang="scss">
.distribution {
  display: grid;
  gap: var(--space-4);
}
.distribution__row {
  display: grid;
  gap: var(--space-2);
}
.distribution__row > div {
  display: flex;
  font-size: var(--font-size-12);
  justify-content: space-between;
}
.distribution__row span {
  color: var(--color-text-muted);
}
.distribution__track {
  background: var(--color-surface-muted);
  border-radius: var(--radius-pill);
  height: 0.5rem;
  overflow: hidden;
}
.distribution__track i {
  background: var(--gradient-data-active);
  border-radius: inherit;
  display: block;
  height: 100%;
  min-width: 3px;
  transform-origin: left;
  transition: transform var(--transition-data);
  width: 100%;
}
.chart-empty {
  color: var(--color-text-subtle);
  margin: auto;
}
</style>
