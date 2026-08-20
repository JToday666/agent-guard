<template>
  <dl
    class="supervision-capsules"
    :class="`supervision-capsules--${density}`"
    aria-label="决策、审批、门控与执行状态"
  >
    <div
      v-for="layer in layers"
      :key="layer.key"
      class="supervision-capsule"
      :class="`supervision-capsule--${layer.tone}`"
      :data-availability="layer.availability"
      :data-supervision-layer="layer.key"
      :title="layer.detail"
    >
      <dt>{{ layer.label }}</dt>
      <dd>{{ layer.value }}</dd>
    </div>
  </dl>
</template>

<script setup lang="ts">
import { computed } from "vue";

import {
  getSupervisionLayerDisplays,
  SHOW_ENFORCEMENT_PANEL,
} from "../../data/evidence/runtime-supervision-display.ts";
import type { ExecutionStepViewModel } from "../../types/dashboard.ts";

defineOptions({ name: "ExecutionSupervisionCapsules" });

const props = withDefaults(
  defineProps<{
    density?: "node" | "list";
    step: ExecutionStepViewModel;
  }>(),
  { density: "node" },
);

// RTE-05 强绑定未具备事件级下发资格时，Enforcement 胶囊常驻“证据不可用”空态，
// 随面板一并隐藏；SHOW_ENFORCEMENT_PANEL 置回 true 即恢复四层展示。
const layers = computed(() =>
  getSupervisionLayerDisplays(props.step).filter(
    (layer) => SHOW_ENFORCEMENT_PANEL || layer.key !== "enforcement",
  ),
);
</script>

<style scoped lang="scss">
.supervision-capsules {
  display: grid;
  gap: 0.35rem;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
  min-width: 0;
}

.supervision-capsule {
  --capsule-tone: var(--color-text-subtle);
  background: color-mix(in srgb, var(--capsule-tone) 7%, var(--color-surface));
  border: 1px solid color-mix(in srgb, var(--capsule-tone) 32%, var(--color-border));
  border-radius: var(--radius-1);
  display: grid;
  gap: 0.08rem;
  min-width: 0;
  padding: 0.32rem 0.42rem;
}

.supervision-capsule--info {
  --capsule-tone: var(--color-active);
}

.supervision-capsule--success {
  --capsule-tone: var(--color-success);
}

.supervision-capsule--warning {
  --capsule-tone: var(--color-warning-strong);
}

.supervision-capsule--danger {
  --capsule-tone: var(--color-danger);
}

.supervision-capsule dt,
.supervision-capsule dd {
  margin: 0;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.supervision-capsule dt {
  color: var(--color-text-subtle);
  font-family: var(--font-family-mono);
  font-size: 0.55rem;
  letter-spacing: 0.03em;
  text-transform: uppercase;
}

.supervision-capsule dd {
  color: var(--capsule-tone);
  font-size: 0.64rem;
  font-weight: var(--font-weight-semibold);
}

.supervision-capsules--list {
  gap: 0.3rem;
  grid-template-columns: repeat(4, minmax(5.5rem, 1fr));
}

.supervision-capsules--list .supervision-capsule {
  padding: 0.38rem 0.5rem;
}

@media (max-width: 60rem) {
  .supervision-capsules--list {
    grid-template-columns: repeat(2, minmax(6rem, 1fr));
  }
}
</style>
