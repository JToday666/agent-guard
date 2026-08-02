<template>
  <div class="trace-timeline" aria-label="按生命周期分组的审计事件">
    <section v-for="group in groups" :key="group.id" class="trace-timeline__group">
      <header class="trace-timeline__group-header">
        <span>{{ group.index }}</span>
        <div>
          <h3>{{ group.title }}</h3>
          <p>{{ group.description }}</p>
        </div>
        <b>{{ group.events.length }}</b>
      </header>
      <ol>
        <li
          v-for="event in group.events"
          :key="event.id"
          :aria-current="selectedEventId === event.id ? 'true' : undefined"
          :class="[
            `trace-timeline__item--${event.decision}`,
            { 'trace-timeline__item--selected': selectedEventId === event.id },
          ]"
          :data-event-id="event.id"
        >
          <span class="trace-timeline__marker" aria-hidden="true"></span>
          <article>
            <header>
              <div>
                <strong>{{ recordTypeLabel(event) }}</strong>
                <span>{{ event.stage }}</span>
              </div>
              <time :datetime="event.occurredAt">{{ event.time }}</time>
            </header>
            <h4>{{ event.tool }}</h4>
            <code>{{ event.resource }}</code>
            <p>{{ event.reason }}</p>
            <footer>
              <StatusBadge :label="eventStatusLabel(event)" :tone="eventStatusTone(event)" />
              <span>风险 {{ event.riskScore ?? "未记录" }}</span>
              <button
                v-if="traceId"
                type="button"
                class="timeline-select-btn"
                @click="emit('select-event', event.id)"
              >
                定位证据
              </button>
              <RouterLink v-else class="page-action" :to="eventLink(event.id)">
                查看证据
              </RouterLink>
            </footer>
          </article>
        </li>
      </ol>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

import type {
  AuditEventRow,
  AuditRecordType,
  NormalizedAuditEvidence,
} from "../../types/dashboard";
import { getInterventionLabel } from "../../data/evidence/trace-evidence";
import {
  getDecisionLabel,
  getDecisionTone,
  type StatusBadgeTone,
} from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({ name: "TraceTimeline" });
const props = defineProps<{
  events: AuditEventRow[];
  normalizedEvents?: NormalizedAuditEvidence[];
  selectedEventId?: string;
  traceId?: string;
}>();
const emit = defineEmits<{ "select-event": [eventId: string] }>();

const normalizedById = computed(
  () => new Map((props.normalizedEvents ?? []).map((event) => [event.auditId, event])),
);

const groupDefinitions = [
  {
    description: "任务、来源与信任等级",
    id: "input_trust",
    index: "01",
    title: "输入与信任",
  },
  {
    description: "上下文组装与模型计划",
    id: "context_intent",
    index: "02",
    title: "上下文与模型意图",
  },
  {
    description: "工具、资源、规则与策略决定",
    id: "tool_policy",
    index: "03",
    title: "工具、资源与策略",
  },
  {
    description: "执行回执、结果处置与审计",
    id: "outcome_audit",
    index: "04",
    title: "执行结果与审计",
  },
] as const;

function eventGroup(event: AuditEventRow): (typeof groupDefinitions)[number]["id"] {
  const normalized = normalizedById.value.get(event.id);
  if (
    normalized?.recordType === "runtime_outcome" ||
    normalized?.recordType === "runtime_observation"
  ) {
    return "outcome_audit";
  }
  const stage = `${event.stage} ${event.eventType}`.toLowerCase();
  if (/source|input|task|message_received/.test(stage)) return "input_trust";
  if (/context|model_call|model_intent/.test(stage)) return "context_intent";
  if (/result|outcome|persist|output_guard|observation/.test(stage)) {
    return "outcome_audit";
  }
  return "tool_policy";
}

const groups = computed(() =>
  groupDefinitions
    .map((definition) => ({
      ...definition,
      events: props.events.filter((event) => eventGroup(event) === definition.id),
    }))
    .filter((group) => group.events.length),
);

function eventLink(eventId: string) {
  return props.traceId
    ? { path: `/evidence/${props.traceId}`, query: { event_id: eventId } }
    : { path: "/investigations", query: { event_id: eventId } };
}

function recordTypeLabel(event: AuditEventRow): string {
  const recordType = normalizedById.value.get(event.id)?.recordType ?? "unknown";
  const labels: Record<AuditRecordType, string> = {
    config_audit: "配置审计",
    policy_evaluation: "策略判定",
    runtime_observation: "运行时观察",
    runtime_outcome: "运行时结果",
    unknown: "审计事件",
  };
  return labels[recordType];
}

function eventStatusLabel(event: AuditEventRow): string {
  const normalized = normalizedById.value.get(event.id);
  if (
    normalized &&
    normalized.recordType !== "policy_evaluation" &&
    normalized.intervention !== "unknown"
  ) {
    return getInterventionLabel(normalized.intervention);
  }
  return getDecisionLabel(event.decision);
}

function eventStatusTone(event: AuditEventRow): StatusBadgeTone {
  const intervention = normalizedById.value.get(event.id)?.intervention;
  if (
    intervention === "pre_execution_deny" ||
    intervention === "tool_result_quarantine" ||
    intervention === "model_output_revision"
  ) {
    return "protective";
  }
  if (intervention === "approval_release") return "success";
  return getDecisionTone(event.decision);
}
</script>

<style scoped lang="scss">
.trace-timeline {
  display: grid;
  gap: var(--space-5);
}

.trace-timeline__group {
  border-top: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-3);
  padding-top: var(--space-3);
}

.trace-timeline__group-header {
  align-items: center;
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 2rem minmax(0, 1fr) auto;
}

.trace-timeline__group-header > span {
  color: var(--color-active);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-bold);
}

.trace-timeline__group-header div {
  display: grid;
  gap: 0.1rem;
}

.trace-timeline__group-header h3,
.trace-timeline__group-header p {
  margin: 0;
}

.trace-timeline__group-header h3 {
  font-size: var(--font-size-13);
}

.trace-timeline__group-header p,
.trace-timeline__group-header b {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.trace-timeline ol {
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}

.trace-timeline li {
  display: grid;
  gap: var(--space-3);
  grid-template-columns: 0.8rem minmax(0, 1fr);
  position: relative;
}

.trace-timeline li:not(:last-child)::before {
  background: var(--color-border);
  bottom: 0;
  content: "";
  left: 0.3rem;
  position: absolute;
  top: 0.75rem;
  width: 1px;
}

.trace-timeline__marker {
  background: var(--color-surface);
  border: 2px solid var(--color-active);
  border-radius: 50%;
  height: 0.7rem;
  margin-top: 0.35rem;
  position: relative;
  width: 0.7rem;
  z-index: 1;
}

.trace-timeline__item--deny .trace-timeline__marker {
  border-color: var(--color-danger);
}

.trace-timeline__item--ask .trace-timeline__marker {
  border-color: var(--color-warning);
}

.trace-timeline article {
  border-bottom: 1px solid var(--color-border);
  display: grid;
  gap: var(--space-2);
  margin-bottom: var(--space-2);
  padding: 0 0 var(--space-3);
}

.trace-timeline__item--selected article {
  background: var(--color-active-soft);
  box-shadow: inset 2px 0 var(--color-active);
  margin-inline: calc(-1 * var(--space-3));
  padding: var(--space-3);
}

.trace-timeline article > header,
.trace-timeline article footer {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}

.trace-timeline article > header {
  justify-content: space-between;
}

.trace-timeline article > header > div {
  align-items: baseline;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.trace-timeline article > header span,
.trace-timeline time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.trace-timeline h4,
.trace-timeline p {
  margin: 0;
}

.trace-timeline h4 {
  font-size: var(--font-size-14);
}

.trace-timeline p {
  color: var(--color-text-muted);
}

.trace-timeline code {
  color: var(--color-text-subtle);
  overflow-wrap: anywhere;
}

.trace-timeline footer {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.trace-timeline footer .page-action,
.timeline-select-btn {
  margin-left: auto;
}

.timeline-select-btn {
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-link);
  cursor: pointer;
  font-size: var(--font-size-11);
  min-height: 1.75rem;
  padding: 0 var(--space-2);
}

.timeline-select-btn:hover {
  border-color: var(--color-active);
}

.timeline-select-btn:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: 2px;
}
</style>
