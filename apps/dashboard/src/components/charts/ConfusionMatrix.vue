<template>
  <table class="conf-matrix">
    <caption class="sr-only">
      {{
        summary
      }}
    </caption>
    <thead>
      <tr>
        <th scope="col"><span class="sr-only">实际情况</span></th>
        <th class="axis-label" scope="col">预测：放行</th>
        <th class="axis-label" scope="col">预测：阻断</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <th class="axis-label" scope="row">实际：恶意</th>
        <td class="conf-cell conf-cell--fn" :style="{ '--heat': heat(fn) }">
          <strong>{{ fn }}</strong
          ><small>漏报 FN</small>
        </td>
        <td class="conf-cell conf-cell--tp" :style="{ '--heat': heat(tp) }">
          <strong>{{ tp }}</strong
          ><small>正确阻断 TP</small>
        </td>
      </tr>
      <tr>
        <th class="axis-label" scope="row">实际：正常</th>
        <td class="conf-cell conf-cell--tn" :style="{ '--heat': heat(tn) }">
          <strong>{{ tn }}</strong
          ><small>正确放行 TN</small>
        </td>
        <td class="conf-cell conf-cell--fp" :style="{ '--heat': heat(fp) }">
          <strong>{{ fp }}</strong
          ><small>误报 FP</small>
        </td>
      </tr>
    </tbody>
  </table>
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
  border-collapse: separate;
  border-spacing: 2px;
  font-size: var(--font-size-13);
  table-layout: fixed;
  width: 100%;
}
.conf-matrix th:first-child {
  width: 6rem;
}
.axis-label {
  color: var(--color-text-subtle);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  padding: var(--space-2);
  text-align: center;
  vertical-align: middle;
}
.conf-cell {
  height: 4.5rem;
  min-height: 4.5rem;
  padding: var(--space-3);
  text-align: center;
  vertical-align: middle;
}
.conf-cell strong {
  display: block;
  font-size: var(--font-size-24);
  font-weight: var(--font-weight-bold);
  line-height: 1;
}
.conf-cell small {
  display: block;
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
