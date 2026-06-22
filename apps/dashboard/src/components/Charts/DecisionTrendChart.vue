<template>
  <div class="trend-chart">
    <div class="chart-key" aria-label="图例">
      <span><i class="key-allow"></i>放行</span>
      <span><i class="key-ask"></i>审批</span>
      <span><i class="key-deny"></i>拒绝</span>
    </div>
    <div v-if="points.length" class="trend-bars" :aria-label="summary" role="img">
      <div v-for="point in points" :key="point.label" class="trend-group">
        <div class="trend-group__bars">
          <span class="bar bar--allow" :style="getBarHeightStyle(point.allow)" :title="`${point.label} 放行 ${point.allow}`"></span>
          <span class="bar bar--ask" :style="getBarHeightStyle(point.ask)" :title="`${point.label} 审批 ${point.ask}`"></span>
          <span class="bar bar--deny" :style="getBarHeightStyle(point.deny)" :title="`${point.label} 拒绝 ${point.deny}`"></span>
        </div>
        <small>{{ point.label }}</small>
      </div>
    </div>
    <p v-else class="chart-empty">暂无可绘制的时间序列</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import type { DecisionTrendPoint } from "../../types/dashboard";
const props = defineProps<{ points: DecisionTrendPoint[] }>();
const maxValue = computed(() => Math.max(1, ...props.points.flatMap((point) => [point.allow, point.ask, point.deny])));
const summary = computed(() => `决策趋势，共 ${props.points.length} 个时间段`);
function getBarHeightStyle(value: number) { return { height: `${Math.max(value ? 10 : 2, (value / maxValue.value) * 100)}%` }; }
</script>

<style scoped lang="scss">
.trend-chart { display: grid; gap: var(--space-4); min-height: 13rem; }
.chart-key { display: flex; flex-wrap: wrap; gap: var(--space-4); }
.chart-key span { align-items: center; color: var(--color-text-muted); display: inline-flex; font-size: var(--font-size-12); gap: var(--space-2); }
.chart-key i { border-radius: 2px; height: 0.55rem; width: 0.55rem; }
.key-allow { background: var(--color-active); }
.key-ask { background: var(--color-warning); }
.key-deny { background: var(--color-danger); }
.trend-bars { align-items: end; border-bottom: 1px solid var(--color-border); display: flex; gap: var(--space-3); height: 9rem; padding: var(--space-2) var(--space-2) 0; }
.trend-group { display: grid; flex: 1 1 0; gap: var(--space-2); height: 100%; min-width: 2.5rem; }
.trend-group__bars { align-items: end; display: flex; gap: 3px; height: calc(100% - 1.5rem); justify-content: center; }
.bar { border-radius: 3px 3px 0 0; flex: 1 1 0; max-width: 1rem; min-height: 2px; }
.bar--allow { background: var(--color-active); }
.bar--ask { background: var(--color-warning); }
.bar--deny { background: var(--color-danger); }
.trend-group small { color: var(--color-text-subtle); font-size: var(--font-size-11); text-align: center; }
.chart-empty { color: var(--color-text-subtle); margin: auto; }
</style>
