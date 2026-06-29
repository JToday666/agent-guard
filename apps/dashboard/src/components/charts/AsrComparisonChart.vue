<template>
  <figure class="asr-chart" :aria-label="summary">
    <figcaption><strong>攻击成功率变化</strong><span>同一尺度比较防护效果</span></figcaption>
    <div class="asr-chart__scale" aria-hidden="true"><span>0%</span><span>50%</span><span>100%</span></div>
    <div class="asr-chart__track">
      <span class="asr-chart__before" :style="{ width: percent(before) }"></span>
      <span class="asr-chart__after" :style="{ width: percent(after) }"></span>
    </div>
    <div class="asr-chart__labels">
      <div><i class="before"></i><span>防护前</span><strong>{{ percent(before) }}</strong></div>
      <div><i class="after"></i><span>防护后</span><strong>{{ percent(after) }}</strong></div>
      <div class="asr-chart__delta"><span>ASR 降幅</span><strong>{{ reduction }}</strong></div>
    </div>
  </figure>
</template>

<script setup lang="ts">
import { computed } from "vue";
const props = defineProps<{ after: number | null; before: number | null }>();
function percent(value: number | null) { return value === null ? "--" : `${(value * 100).toFixed(1)}%`; }
const reduction = computed(() => props.before === null || props.after === null ? "--" : `${((props.before - props.after) * 100).toFixed(1)}pp`);
const summary = computed(() => `防护前攻击成功率 ${percent(props.before)}，防护后 ${percent(props.after)}，降幅 ${reduction.value}`);
</script>

<style scoped lang="scss">
.asr-chart { border-block: 1px solid var(--color-border); display: grid; gap: var(--space-4); margin: 0; padding: var(--space-5) 0; }
.asr-chart figcaption { display: grid; }
.asr-chart figcaption span, .asr-chart__scale { color: var(--color-text-subtle); font-size: var(--font-size-12); }
.asr-chart__scale { display: flex; justify-content: space-between; }
.asr-chart__track { background: var(--color-surface-muted); height: 2.75rem; overflow: hidden; position: relative; }
.asr-chart__track span { bottom: 0; left: 0; position: absolute; transition: width var(--transition-base); }
.asr-chart__before { background: var(--color-danger-soft); border-right: 2px solid var(--color-danger); height: 100%; }
.asr-chart__after { background: var(--color-success); height: .6rem; }
.asr-chart__labels { align-items: center; display: flex; flex-wrap: wrap; gap: var(--space-5); }
.asr-chart__labels > div { align-items: center; display: flex; gap: var(--space-2); }
.asr-chart__labels i { border-radius: 50%; height: .625rem; width: .625rem; }
.asr-chart__labels i.before { background: var(--color-danger); }
.asr-chart__labels i.after { background: var(--color-success); }
.asr-chart__delta { margin-left: auto; }
.asr-chart__delta strong { color: var(--color-success); font-size: var(--font-size-24); }
</style>
