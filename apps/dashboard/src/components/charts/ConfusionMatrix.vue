<template>
  <div class="conf-matrix" :aria-label="summary" role="img">
    <div class="conf-matrix__header">
      <span></span><span class="axis-label">预测：放行</span
      ><span class="axis-label">预测：阻断</span>
    </div>
    <div class="conf-matrix__row">
      <span class="axis-label">实际：恶意</span>
      <div
        class="conf-cell conf-cell--fn"
        :aria-label="`漏报 FN，${fn}`"
        :style="{ '--heat': heat(fn) }"
        tabindex="0"
      >
        <strong>{{ fn }}</strong
        ><small>漏报 FN</small>
      </div>
      <div
        class="conf-cell conf-cell--tp"
        :aria-label="`正确阻断 TP，${tp}`"
        :style="{ '--heat': heat(tp) }"
        tabindex="0"
      >
        <strong>{{ tp }}</strong
        ><small>正确阻断 TP</small>
      </div>
    </div>
    <div class="conf-matrix__row">
      <span class="axis-label">实际：正常</span>
      <div
        class="conf-cell conf-cell--tn"
        :aria-label="`正确放行 TN，${tn}`"
        :style="{ '--heat': heat(tn) }"
        tabindex="0"
      >
        <strong>{{ tn }}</strong
        ><small>正确放行 TN</small>
      </div>
      <div
        class="conf-cell conf-cell--fp"
        :aria-label="`误报 FP，${fp}`"
        :style="{ '--heat': heat(fp) }"
        tabindex="0"
      >
        <strong>{{ fp }}</strong
        ><small>误报 FP</small>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

defineOptions({ name: "ConfusionMatrix" });
const props = defineProps<{ tp: number; fp: number; tn: number; fn: number }>();
const maxValue = computed(() => Math.max(1, props.tp, props.fp, props.tn, props.fn));
const summary = computed(
  () => `混淆矩阵：正确阻断 ${props.tp}，误报 ${props.fp}，正确放行 ${props.tn}，漏报 ${props.fn}`,
);
function heat(value: number): string {
  return `${18 + Math.round((value / maxValue.value) * 38)}%`;
}
</script>

<style scoped lang="scss">
.conf-matrix {
  display: grid;
  font-size: var(--font-size-13);
  gap: 2px;
}
.conf-matrix__header {
  display: grid;
  gap: 2px;
  grid-template-columns: 6rem 1fr 1fr;
}
.conf-matrix__row {
  display: grid;
  gap: 2px;
  grid-template-columns: 6rem 1fr 1fr;
}
.axis-label {
  align-items: center;
  color: var(--color-text-subtle);
  display: flex;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  justify-content: center;
  padding: var(--space-2);
  text-align: center;
}
.conf-cell {
  display: grid;
  gap: var(--space-1);
  min-height: 4.5rem;
  padding: var(--space-3);
  place-items: center;
  text-align: center;
}
.conf-cell strong {
  font-size: var(--font-size-24);
  font-weight: var(--font-weight-bold);
  line-height: 1;
}
.conf-cell:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: -3px;
}
.conf-cell small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.conf-cell--tp {
  background: color-mix(in srgb, var(--color-success) var(--heat), var(--color-surface));
  border: 1px solid var(--color-success-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-success);
  }
}
.conf-cell--tn {
  background: color-mix(in srgb, var(--color-success) var(--heat), var(--color-surface));
  border: 1px solid var(--color-success-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-success);
  }
}
.conf-cell--fp {
  background: color-mix(in srgb, var(--color-warning) var(--heat), var(--color-surface));
  border: 1px solid var(--color-warning-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-warning);
  }
}
.conf-cell--fn {
  background: color-mix(in srgb, var(--color-danger) var(--heat), var(--color-surface));
  border: 1px solid var(--color-danger-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-danger);
  }
}
</style>
