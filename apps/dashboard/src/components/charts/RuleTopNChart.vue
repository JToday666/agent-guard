<template>
  <ol v-if="items.length" class="rule-topn" aria-label="规则命中 TopN">
    <li v-for="item in items" :key="item.label" class="rule-topn__row">
      <div class="rule-topn__meta">
        <span class="rule-topn__id" :title="ruleLabel(item.label)">{{
          ruleLabel(item.label)
        }}</span>
        <strong>{{ item.value }}</strong>
      </div>
      <span class="rule-topn__track"
        ><i :style="{ transform: `scaleX(${item.value / maxValue})` }"></i
      ></span>
    </li>
  </ol>
  <p v-else class="chart-empty">暂无规则命中数据</p>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { ruleLabel } from "../../utils/rule-display";
defineOptions({ name: "RuleTopNChart" });
const props = defineProps<{ items: Array<{ label: string; value: number }> }>();
const maxValue = computed(() => Math.max(1, ...props.items.map((i) => i.value)));
</script>

<style scoped lang="scss">
.rule-topn {
  display: grid;
  gap: var(--space-3);
  list-style: none;
  margin: 0;
  padding: 0;
}
.rule-topn__row {
  display: grid;
  gap: var(--space-2);
}
.rule-topn__meta {
  align-items: baseline;
  display: flex;
  font-size: var(--font-size-12);
  gap: var(--space-2);
  justify-content: space-between;
}
.rule-topn__id {
  background: var(--color-surface-muted);
  border-radius: var(--radius-1);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-11);
  max-width: 12rem;
  overflow: hidden;
  padding: 0.1em 0.4em;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.rule-topn__track {
  background: var(--color-surface-muted);
  border-radius: var(--radius-pill);
  display: block;
  height: 0.5rem;
  overflow: hidden;
}
.rule-topn__track i {
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
  margin: 0;
}
</style>
