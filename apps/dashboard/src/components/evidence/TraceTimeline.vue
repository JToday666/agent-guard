<template>
  <ol class="trace-timeline" aria-label="证据链审计事件">
    <li
      v-for="(event, index) in events"
      :key="event.id"
      :aria-current="selectedEventId === event.id ? 'true' : undefined"
      :class="[
        `trace-timeline__item--${event.decision}`,
        { 'trace-timeline__item--selected': selectedEventId === event.id },
      ]"
      :data-event-id="event.id"
    >
      <span class="trace-timeline__marker" aria-hidden="true">{{ index + 1 }}</span>
      <article>
        <header>
          <strong>{{ event.stage }}</strong
          ><time :datetime="event.occurredAt">{{ event.time }}</time>
        </header>
        <h3>{{ event.tool }}</h3>
        <code>{{ event.resource }}</code>
        <p>{{ event.reason }}</p>
        <footer>
          <StatusBadge
            :label="getDecisionLabel(event.decision)"
            :tone="getDecisionTone(event.decision)"
          />
          <span>风险 {{ event.riskScore }}</span>
          <button
            v-if="traceId"
            type="button"
            class="timeline-select-btn"
            @click="emit('select-event', event.id)"
          >
            定位并查看证据
          </button>
          <RouterLink v-else class="page-action" :to="eventLink(event.id)">查看证据</RouterLink>
        </footer>
      </article>
    </li>
  </ol>
</template>

<script setup lang="ts">
import type { AuditEventRow } from "../../types/dashboard";
import { getDecisionLabel, getDecisionTone } from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";

defineOptions({ name: "TraceTimeline" });
const props = defineProps<{
  events: AuditEventRow[];
  selectedEventId?: string;
  traceId?: string;
}>();
const emit = defineEmits<{ "select-event": [eventId: string] }>();
function eventLink(eventId: string) {
  return props.traceId
    ? { path: `/evidence/${props.traceId}`, query: { event_id: eventId } }
    : { path: "/investigations", query: { event_id: eventId } };
}
</script>

<style scoped lang="scss">
.trace-timeline {
  display: grid;
  list-style: none;
  margin: 0;
  padding: 0;
}
.trace-timeline li {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: 2rem minmax(0, 1fr);
  position: relative;
}
.trace-timeline li:not(:last-child)::before {
  background: var(--color-border);
  bottom: 0;
  content: "";
  left: 0.9375rem;
  position: absolute;
  top: 2rem;
  width: 2px;
}
.trace-timeline__marker {
  align-items: center;
  background: var(--color-surface);
  border: 2px solid var(--color-active);
  border-radius: 50%;
  display: flex;
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-bold);
  height: 2rem;
  justify-content: center;
  position: relative;
  width: 2rem;
  z-index: 1;
}
.trace-timeline__item--deny .trace-timeline__marker {
  border-color: var(--color-danger);
  color: var(--color-danger);
}
.trace-timeline__item--ask .trace-timeline__marker {
  border-color: var(--color-warning);
  color: var(--color-warning);
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
.trace-timeline article header,
.trace-timeline article footer {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.trace-timeline article header {
  justify-content: space-between;
}
.trace-timeline h3,
.trace-timeline p {
  margin: 0;
}
.trace-timeline h3 {
  font-size: var(--font-size-16);
}
.trace-timeline p,
.trace-timeline time {
  color: var(--color-text-muted);
}
.trace-timeline code {
  color: var(--color-text-subtle);
  overflow-wrap: anywhere;
}
.trace-timeline footer .page-action {
  margin-left: auto;
}
.timeline-select-btn {
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  color: var(--color-text-subtle);
  cursor: pointer;
  font-size: var(--font-size-11);
  min-height: 1.75rem;
  padding: 0 var(--space-2);
}
.timeline-select-btn:hover {
  border-color: var(--color-active);
  color: var(--color-active);
}
</style>
