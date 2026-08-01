<template>
  <div class="conf-matrix" aria-label="混淆矩阵">
    <div class="conf-matrix__header">
      <span></span><span class="axis-label">预测：放行</span><span class="axis-label">预测：阻断</span>
    </div>
    <div class="conf-matrix__row">
      <span class="axis-label">实际：恶意</span>
      <div class="conf-cell conf-cell--fn">
        <strong>{{ fn }}</strong
        ><small>漏报 FN</small>
      </div>
      <div class="conf-cell conf-cell--tp">
        <strong>{{ tp }}</strong
        ><small>正确阻断 TP</small>
      </div>
    </div>
    <div class="conf-matrix__row">
      <span class="axis-label">实际：正常</span>
      <div class="conf-cell conf-cell--tn">
        <strong>{{ tn }}</strong
        ><small>正确放行 TN</small>
      </div>
      <div class="conf-cell conf-cell--fp">
        <strong>{{ fp }}</strong
        ><small>误报 FP</small>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
defineOptions({ name: "ConfusionMatrix" });
defineProps<{ tp: number; fp: number; tn: number; fn: number }>();
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
.conf-cell small {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}
.conf-cell--tp {
  background: var(--color-success-soft);
  border: 1px solid var(--color-success-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-success);
  }
}
.conf-cell--tn {
  background: var(--color-success-soft);
  border: 1px solid var(--color-success-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-success);
  }
}
.conf-cell--fp {
  background: var(--color-warning-soft);
  border: 1px solid var(--color-warning-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-warning);
  }
}
.conf-cell--fn {
  background: var(--color-danger-soft);
  border: 1px solid var(--color-danger-border);
  border-radius: var(--radius-2);
  strong {
    color: var(--color-danger);
  }
}
</style>
