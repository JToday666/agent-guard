<template>
  <figure class="trend-chart">
    <div v-if="points.length" class="trend-legend" aria-hidden="true">
      <span class="series-allow"><i></i>允许</span>
      <span class="series-ask"><i></i>需审批</span>
      <span class="series-deny"><i></i>拒绝</span>
    </div>
    <svg
      v-if="points.length"
      viewBox="0 0 720 240"
      role="img"
      :aria-label="activeSummary"
      preserveAspectRatio="xMidYMid meet"
      tabindex="0"
      @focus="ensureActivePoint"
      @keydown="handleKeydown"
      @pointerleave="handlePointerLeave"
    >
      <title>{{ activeSummary }}</title>
      <g class="grid-lines" aria-hidden="true">
        <g v-for="tick in yTicks" :key="tick.y">
          <text x="25" :y="tick.y + 4" text-anchor="end">{{ tick.value }}</text>
          <line x1="36" :y1="tick.y" x2="650" :y2="tick.y" />
        </g>
      </g>
      <polyline
        v-for="series in chartSeries"
        :key="series.label"
        :class="series.className"
        :points="series.points"
        fill="none"
        vector-effect="non-scaling-stroke"
      />
      <g v-for="series in chartSeries" :key="`${series.label}-label`" :class="series.className">
        <circle :cx="series.lastX" :cy="series.lastY" r="4" vector-effect="non-scaling-stroke" />
        <line
          class="label-connector"
          :x1="series.lastX + 6"
          :y1="series.lastY"
          x2="660"
          :y2="series.labelY"
          vector-effect="non-scaling-stroke"
        />
        <text x="665" :y="series.labelY + 4">{{ series.lastValue }}</text>
      </g>
      <rect
        class="trend-hit-area"
        x="24"
        y="20"
        width="626"
        height="200"
        aria-hidden="true"
        @pointerenter="handlePointerEnter"
        @pointermove="handlePointerMove"
      />
      <g v-if="activePoint" class="trend-inspector" aria-hidden="true">
        <line class="trend-inspector__guide" :x1="activeX" y1="24" :x2="activeX" y2="216" />
        <circle
          v-for="series in activeSeries"
          :key="`active-${series.key}`"
          :class="series.className"
          :cx="activeX"
          :cy="series.y"
          r="5"
        />
        <g :transform="`translate(${tooltipPosition.x} ${tooltipPosition.y})`">
          <rect class="trend-inspector__surface" width="140" height="76" rx="4" />
          <text class="trend-inspector__title" x="10" y="17">{{ activePoint.label }}</text>
          <text class="series-allow" x="10" y="35">允许 {{ activePoint.allow }}</text>
          <text class="series-ask" x="10" y="52">需审批 {{ activePoint.ask }}</text>
          <text class="series-deny" x="10" y="69">拒绝 {{ activePoint.deny }}</text>
        </g>
      </g>
      <g class="x-labels">
        <text v-for="label in xLabels" :key="label.index" :x="label.x" y="236" text-anchor="middle">
          {{ label.text }}
        </text>
      </g>
    </svg>
    <p v-else class="chart-empty">暂无可绘制的时间序列</p>
    <figcaption v-if="points.length">
      最新时间段：允许 {{ latest.allow }}、需审批 {{ latest.ask }}、拒绝 {{ latest.deny }}
    </figcaption>
  </figure>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { DecisionTrendPoint } from "../../types/dashboard";
const props = defineProps<{ points: DecisionTrendPoint[] }>();
const activeIndex = ref<number | null>(null);
let pointerBounds: DOMRect | null = null;
const latest = computed(() => props.points.at(-1) ?? { allow: 0, ask: 0, deny: 0, label: "" });
const maxValue = computed(() =>
  Math.max(1, ...props.points.flatMap((point) => [point.allow, point.ask, point.deny])),
);
const yAxisStep = computed(() => (maxValue.value <= 4 ? 1 : Math.ceil(maxValue.value / 4)));
const yAxisMax = computed(() => Math.ceil(maxValue.value / yAxisStep.value) * yAxisStep.value);
const xStep = computed(() => (props.points.length > 1 ? 626 / (props.points.length - 1) : 0));
function xPosition(index: number): number {
  return props.points.length > 1 ? 24 + index * xStep.value : 337;
}
const yTicks = computed(() => {
  const values: number[] = [];
  for (let value = yAxisMax.value; value > 0; value -= yAxisStep.value) {
    values.push(value);
  }
  values.push(0);
  return values.map((value) => ({
    value,
    y: 24 + (1 - value / yAxisMax.value) * 192,
  }));
});
const xLabels = computed(() => {
  const maxLabels = 6;
  const labelStep =
    props.points.length > maxLabels ? Math.ceil((props.points.length - 1) / (maxLabels - 1)) : 1;
  return props.points.flatMap((point, index) =>
    index % labelStep === 0 || index === props.points.length - 1
      ? [{ index, text: point.label, x: xPosition(index) }]
      : [],
  );
});
const chartSeries = computed(() => {
  const seriesItems = (
    [
      { className: "series-allow", key: "allow", label: "允许" },
      { className: "series-ask", key: "ask", label: "需审批" },
      { className: "series-deny", key: "deny", label: "拒绝" },
    ] as const
  ).map((series) => {
    const coordinates = props.points.map((point, index) => ({
      x: xPosition(index),
      y: 216 - (point[series.key] / yAxisMax.value) * 192,
    }));
    const last = coordinates.at(-1) ?? { x: 24, y: 216 };
    return {
      ...series,
      coordinates,
      labelY: last.y,
      lastValue: latest.value[series.key],
      lastX: last.x,
      lastY: last.y,
      points: coordinates.map((point) => `${point.x},${point.y}`).join(" "),
    };
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
const activePoint = computed(() =>
  activeIndex.value === null ? null : (props.points[activeIndex.value] ?? null),
);
const activeX = computed(() => (activeIndex.value === null ? 24 : xPosition(activeIndex.value)));
const activeSeries = computed(() =>
  chartSeries.value.map((series) => ({
    className: series.className,
    key: series.key,
    y: activeIndex.value === null ? 216 : (series.coordinates[activeIndex.value]?.y ?? 216),
  })),
);
const tooltipPosition = computed(() => ({
  x: activeX.value > 500 ? activeX.value - 150 : activeX.value + 10,
  y: 30,
}));
const summary = computed(
  () =>
    `决策趋势，共 ${props.points.length} 个时间段。最新：允许 ${latest.value.allow}，需审批 ${latest.value.ask}，拒绝 ${latest.value.deny}`,
);
const activeSummary = computed(() =>
  activePoint.value
    ? `决策趋势，${activePoint.value.label}：允许 ${activePoint.value.allow}，需审批 ${activePoint.value.ask}，拒绝 ${activePoint.value.deny}。使用左右方向键查看相邻时间段`
    : `${summary.value}。聚焦图表后可使用左右方向键查看各时间段`,
);
watch(
  () => props.points.length,
  (length) => {
    if (activeIndex.value === null || activeIndex.value < length) return;
    activeIndex.value = length ? length - 1 : null;
  },
);

function ensureActivePoint() {
  if (activeIndex.value === null) activeIndex.value = Math.max(0, props.points.length - 1);
}

function handlePointerEnter(event: PointerEvent) {
  pointerBounds = (event.currentTarget as SVGGraphicsElement).getBoundingClientRect();
}

function handlePointerMove(event: PointerEvent) {
  const bounds =
    pointerBounds ?? (event.currentTarget as SVGGraphicsElement).getBoundingClientRect();
  if (!bounds || !props.points.length) return;
  const chartX = 24 + ((event.clientX - bounds.left) / bounds.width) * 626;
  const index =
    props.points.length === 1
      ? 0
      : Math.round((Math.min(650, Math.max(24, chartX)) - 24) / xStep.value);
  activeIndex.value = Math.min(props.points.length - 1, Math.max(0, index));
}

function handlePointerLeave() {
  pointerBounds = null;
  activeIndex.value = null;
}

function handleKeydown(event: KeyboardEvent) {
  if (!props.points.length) return;
  if (event.key === "Escape") {
    activeIndex.value = null;
    return;
  }
  const current = activeIndex.value ?? props.points.length - 1;
  const target =
    event.key === "ArrowLeft"
      ? Math.max(0, current - 1)
      : event.key === "ArrowRight"
        ? Math.min(props.points.length - 1, current + 1)
        : event.key === "Home"
          ? 0
          : event.key === "End"
            ? props.points.length - 1
            : null;
  if (target === null) return;
  event.preventDefault();
  activeIndex.value = target;
}
</script>

<style scoped lang="scss">
.trend-chart {
  display: grid;
  gap: var(--space-3);
  margin: 0;
  min-height: 15rem;
}
.trend-legend {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.trend-legend span {
  align-items: center;
  display: inline-flex;
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  gap: var(--space-1);
}
.trend-legend i {
  border-radius: var(--radius-pill);
  display: inline-block;
  height: 0.1875rem;
  width: 1.25rem;
}
.trend-legend .series-allow i {
  background: var(--gradient-line-slate);
}
.trend-legend .series-ask i {
  background: var(--gradient-line-warning);
}
.trend-legend .series-deny i {
  background: var(--color-chart-primary);
}
.trend-chart svg {
  height: 15rem;
  overflow: visible;
  width: 100%;
}
.trend-chart svg:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: 3px;
}
.grid-lines line {
  stroke: var(--color-chart-grid);
  stroke-width: 1;
}
.grid-lines text {
  fill: var(--color-text-subtle);
  font-size: 11px;
  font-weight: var(--font-weight-medium);
  stroke: none;
}
.trend-chart polyline {
  fill: none;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2.5;
}
.label-connector {
  opacity: 0.45;
  stroke-width: 1;
}
.trend-chart circle {
  fill: var(--color-surface);
  stroke-width: 2;
}
.trend-hit-area {
  cursor: crosshair;
  fill: transparent;
  pointer-events: all;
}
.trend-inspector {
  pointer-events: none;
}
.trend-inspector__guide {
  opacity: 0.7;
  stroke: var(--color-border-strong);
  stroke-dasharray: 3 3;
  stroke-width: 1;
}
.trend-inspector__surface {
  fill: color-mix(in srgb, var(--color-surface) 96%, transparent);
  filter: var(--filter-chart-primary);
  stroke: var(--color-border-strong);
}
.trend-inspector text {
  font-size: 11px;
  font-weight: var(--font-weight-semibold);
  stroke: none;
}
.trend-inspector__title {
  fill: var(--color-text);
}
.series-allow {
  fill: var(--color-chart-slate);
  stroke: var(--color-chart-slate);
  stroke-dasharray: 6 4;
}
.series-ask {
  fill: var(--color-chart-warning);
  stroke: var(--color-chart-warning);
  stroke-dasharray: 2 4;
}
.series-deny {
  fill: var(--color-chart-primary);
  filter: var(--filter-chart-primary);
  stroke: var(--color-chart-primary);
}
.trend-chart text {
  font-size: 12px;
  font-weight: var(--font-weight-semibold);
}
.x-labels {
  fill: var(--color-text-subtle);
  stroke: none;
}
.trend-chart figcaption,
.chart-empty {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  margin: 0;
}
.chart-empty {
  margin: auto;
}
</style>
