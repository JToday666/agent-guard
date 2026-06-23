<template>
  <figure class="trend-chart">
    <svg v-if="points.length" viewBox="0 0 720 240" role="img" :aria-label="summary" preserveAspectRatio="xMidYMid meet">
      <g class="grid-lines" aria-hidden="true"><line v-for="y in [24, 72, 120, 168, 216]" :key="y" x1="24" :y1="y" x2="650" :y2="y" /></g>
      <polyline v-for="series in chartSeries" :key="series.label" :class="series.className" :points="series.points" fill="none" vector-effect="non-scaling-stroke" />
      <g v-for="series in chartSeries" :key="`${series.label}-label`" :class="series.className">
        <circle :cx="series.lastX" :cy="series.lastY" r="4" vector-effect="non-scaling-stroke" />
        <line class="label-connector" :x1="series.lastX + 6" :y1="series.lastY" x2="660" :y2="series.labelY" vector-effect="non-scaling-stroke" />
        <text x="665" :y="series.labelY + 4">{{ series.label }} {{ series.lastValue }}</text>
      </g>
      <g class="x-labels"><text v-for="label in xLabels" :key="label.text" :x="label.x" y="236" text-anchor="middle">{{ label.text }}</text></g>
    </svg>
    <p v-else class="chart-empty">暂无可绘制的时间序列</p>
    <figcaption v-if="points.length">最新时间段：放行 {{ latest.allow }}、审批 {{ latest.ask }}、拒绝 {{ latest.deny }}</figcaption>
  </figure>
</template>

<script setup lang="ts">
import { computed } from "vue";
import type { DecisionTrendPoint } from "../../types/dashboard";
const props = defineProps<{ points: DecisionTrendPoint[] }>();
const latest = computed(() => props.points.at(-1) ?? { allow: 0, ask: 0, deny: 0, label: "" });
const maxValue = computed(() => Math.max(1, ...props.points.flatMap((point) => [point.allow, point.ask, point.deny])));
const xStep = computed(() => props.points.length > 1 ? 626 / (props.points.length - 1) : 0);
const xLabels = computed(() => props.points.map((point, index) => ({ text: point.label, x: 24 + index * xStep.value })));
const chartSeries = computed(() => {
  const seriesItems = ([
  { className: "series-allow", key: "allow", label: "放行" },
  { className: "series-ask", key: "ask", label: "审批" },
  { className: "series-deny", key: "deny", label: "拒绝" },
] as const).map((series) => {
  const coordinates = props.points.map((point, index) => ({ x: 24 + index * xStep.value, y: 216 - (point[series.key] / maxValue.value) * 192 }));
  const last = coordinates.at(-1) ?? { x: 24, y: 216 };
    return { ...series, labelY: last.y, lastValue: latest.value[series.key], lastX: last.x, lastY: last.y, points: coordinates.map((point) => `${point.x},${point.y}`).join(" ") };
  });
  const sortedItems = [...seriesItems].sort((left, right) => left.lastY - right.lastY);
  let previousLabelY = -16;
  for (const item of sortedItems) {
    item.labelY = Math.max(item.lastY, previousLabelY + 16);
    previousLabelY = item.labelY;
  }
  const overflow = Math.max(0, previousLabelY - 210);
  for (const item of sortedItems) item.labelY -= overflow;
  return seriesItems;
});
const summary = computed(() => `决策趋势，共 ${props.points.length} 个时间段。最新：放行 ${latest.value.allow}，审批 ${latest.value.ask}，拒绝 ${latest.value.deny}`);
</script>

<style scoped lang="scss">
.trend-chart { display: grid; gap: var(--space-2); margin: 0; min-height: 15rem; }
.trend-chart svg { height: 15rem; overflow: visible; width: 100%; }
.grid-lines line { stroke: var(--color-border); stroke-width: 1; }
.trend-chart polyline { stroke-linecap: round; stroke-linejoin: round; stroke-width: 2.5; }
.label-connector { opacity: .45; stroke-width: 1; }
.trend-chart circle { fill: var(--color-surface); stroke-width: 2; }
.series-allow { fill: var(--color-active); stroke: var(--color-active); }
.series-ask { fill: var(--color-warning); stroke: var(--color-warning); }
.series-deny { fill: var(--color-danger); stroke: var(--color-danger); }
.trend-chart text { font-size: 11px; font-weight: var(--font-weight-semibold); }
.x-labels { fill: var(--color-text-subtle); stroke: none; }
.trend-chart figcaption, .chart-empty { color: var(--color-text-subtle); font-size: var(--font-size-12); margin: 0; }
.chart-empty { margin: auto; }
</style>
