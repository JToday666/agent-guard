<template>
  <div
    ref="rootElement"
    class="app-select"
    :class="{ 'app-select--disabled': disabled, 'app-select--open': isOpen }"
  >
    <label :id="labelId" class="app-select__label" :for="triggerId">{{ label }}</label>
    <button
      :id="triggerId"
      ref="triggerElement"
      class="app-select__trigger"
      type="button"
      :aria-activedescendant="isOpen ? activeOptionId : undefined"
      :aria-controls="listboxId"
      aria-haspopup="listbox"
      :aria-expanded="isOpen"
      :aria-labelledby="`${labelId} ${valueId}`"
      :disabled="disabled"
      role="combobox"
      @click="handleTriggerClick"
      @keydown="handleKeydown"
    >
      <span
        :id="valueId"
        class="app-select__value"
        :class="{ 'app-select__value--placeholder': !selectedOption }"
      >
        {{ selectedOption?.label ?? placeholder }}
      </span>
      <ChevronDown class="app-select__icon" aria-hidden="true" :size="16" />
    </button>

    <Transition name="app-select-menu">
      <ul
        v-if="isOpen"
        :id="listboxId"
        class="app-select__menu"
        role="listbox"
        :aria-labelledby="labelId"
      >
        <li
          v-for="(option, index) in options"
          :id="getOptionId(index)"
          :key="option.value"
          class="app-select__option"
          :class="{
            'app-select__option--active': index === activeIndex,
            'app-select__option--selected': option.value === modelValue,
          }"
          role="option"
          :aria-selected="option.value === modelValue"
          @click="handleSelect(option.value)"
          @mouseenter="activeIndex = index"
        >
          <span>{{ option.label }}</span>
          <Check v-if="option.value === modelValue" aria-hidden="true" :size="15" />
        </li>
      </ul>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { Check, ChevronDown } from "@lucide/vue";
import { computed, nextTick, onBeforeUnmount, onDeactivated, ref, useId, watch } from "vue";

defineOptions({
  name: "AppSelect",
});

interface SelectOption {
  label: string;
  value: string;
}

const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

const props = withDefaults(
  defineProps<{
    disabled?: boolean;
    id?: string;
    label: string;
    modelValue: string;
    options: SelectOption[];
    placeholder?: string;
  }>(),
  {
    disabled: false,
    id: undefined,
    placeholder: "请选择",
  },
);

const rootElement = ref<HTMLElement | null>(null);
const triggerElement = ref<HTMLButtonElement | null>(null);
const isOpen = ref(false);
const activeIndex = ref(0);
const instanceId = useId();
const baseId = computed(() => props.id ?? instanceId);
const triggerId = computed(() => `${baseId.value}-trigger`);
const labelId = computed(() => `${baseId.value}-label`);
const valueId = computed(() => `${baseId.value}-value`);
const listboxId = computed(() => `${baseId.value}-listbox`);
const activeOptionId = computed(() => getOptionId(activeIndex.value));
const selectedOption = computed(() =>
  props.options.find((option) => option.value === props.modelValue),
);
let typeaheadBuffer = "";
let typeaheadTimer: number | undefined;

watch(
  [() => props.modelValue, () => props.options, () => props.disabled],
  () => {
    if (props.disabled || props.options.length === 0) handleClose();
    activeIndex.value = getSelectedIndex();
  },
  { immediate: true },
);

onDeactivated(handleClose);
onBeforeUnmount(handleClose);

function handleTriggerClick(): void {
  if (props.disabled) return;
  if (isOpen.value) {
    handleClose();
    return;
  }
  handleOpen();
}

function handleOpen(): void {
  if (props.disabled || props.options.length === 0) return;
  activeIndex.value = getSelectedIndex();
  isOpen.value = true;
  document.addEventListener("pointerdown", handleDocumentPointerDown);
}

function handleClose(): void {
  isOpen.value = false;
  document.removeEventListener("pointerdown", handleDocumentPointerDown);
  window.clearTimeout(typeaheadTimer);
  typeaheadBuffer = "";
  typeaheadTimer = undefined;
}

function handleMove(direction: number): void {
  if (props.options.length === 0) return;
  activeIndex.value = (activeIndex.value + direction + props.options.length) % props.options.length;
}

function handleSelectActive(): void {
  const option = props.options[activeIndex.value];
  if (!option) return;
  handleSelect(option.value);
}

function handleSelect(value: string): void {
  emit("update:modelValue", value);
  handleClose();
  void nextTick(() => triggerElement.value?.focus());
}

function handleKeydown(event: KeyboardEvent): void {
  if (event.key === "Tab") {
    handleClose();
    return;
  }
  if (event.key === "Escape") {
    event.preventDefault();
    handleClose();
    return;
  }
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    if (isOpen.value) handleSelectActive();
    else handleOpen();
    return;
  }
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    if (isOpen.value) handleMove(event.key === "ArrowDown" ? 1 : -1);
    else handleOpen();
    return;
  }
  if (event.key === "Home" || event.key === "End") {
    event.preventDefault();
    if (props.options.length === 0) return;
    if (!isOpen.value) handleOpen();
    activeIndex.value = event.key === "Home" ? 0 : props.options.length - 1;
    return;
  }
  if (isOpen.value && event.key.length === 1 && !event.altKey && !event.ctrlKey && !event.metaKey) {
    event.preventDefault();
    handleTypeahead(event.key);
  }
}

function handleTypeahead(key: string): void {
  window.clearTimeout(typeaheadTimer);
  const normalizedKey = key.toLocaleLowerCase("zh-CN");
  const isRepeatedKey =
    typeaheadBuffer.length > 0 &&
    [...typeaheadBuffer].every((character) => character === normalizedKey);
  typeaheadBuffer = isRepeatedKey ? normalizedKey : `${typeaheadBuffer}${normalizedKey}`;

  for (let offset = 1; offset <= props.options.length; offset += 1) {
    const index = (activeIndex.value + offset) % props.options.length;
    if (props.options[index]?.label.toLocaleLowerCase("zh-CN").startsWith(typeaheadBuffer)) {
      activeIndex.value = index;
      break;
    }
  }
  typeaheadTimer = window.setTimeout(() => {
    typeaheadBuffer = "";
    typeaheadTimer = undefined;
  }, 500);
}

function handleDocumentPointerDown(event: PointerEvent): void {
  if (!rootElement.value?.contains(event.target as Node)) {
    handleClose();
  }
}

function getSelectedIndex(): number {
  const selectedIndex = props.options.findIndex((option) => option.value === props.modelValue);
  return selectedIndex >= 0 ? selectedIndex : 0;
}

function getOptionId(index: number): string {
  return `${baseId.value}-option-${index}`;
}
</script>

<style scoped lang="scss">
.app-select {
  display: grid;
  gap: var(--space-1);
  min-width: 0;
  position: relative;
}

.app-select__label {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
  line-height: var(--line-height-ui);
}

.app-select__trigger {
  align-items: center;
  background: var(--gradient-popover);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  box-shadow: var(--shadow-subtle);
  color: var(--color-text);
  cursor: pointer;
  display: grid;
  gap: var(--space-2);
  grid-template-columns: minmax(0, 1fr) auto;
  min-height: 2.5rem;
  min-width: 0;
  padding: 0 var(--space-3);
  text-align: left;
  width: 100%;

  &:hover {
    border-color: var(--color-active-border);
    box-shadow: var(--shadow-subtle);
  }
}

.app-select--open .app-select__trigger {
  border-color: var(--color-active-border);
  box-shadow: var(--shadow-focus);
}

.app-select--disabled {
  opacity: 0.64;

  .app-select__trigger {
    cursor: not-allowed;
  }
}

.app-select__value {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.app-select__value--placeholder {
  color: var(--color-text-subtle);
}

.app-select__icon {
  color: var(--color-text-subtle);
  transition: transform var(--transition-fast);
}

.app-select--open .app-select__icon {
  color: var(--color-active);
  transform: rotate(180deg);
}

.app-select__menu {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-3);
  box-shadow: var(--shadow-raised);
  display: grid;
  gap: var(--space-1);
  left: 0;
  list-style: none;
  margin: var(--space-2) 0 0;
  max-height: 16rem;
  min-width: 100%;
  overflow: auto;
  padding: var(--space-2);
  position: absolute;
  right: 0;
  top: 100%;
  z-index: 40;
}

.app-select__option {
  align-items: center;
  border-radius: var(--radius-2);
  color: var(--color-text-muted);
  cursor: pointer;
  display: grid;
  font-size: var(--font-size-13);
  gap: var(--space-2);
  grid-template-columns: minmax(0, 1fr) auto;
  min-height: 2.25rem;
  padding: 0 var(--space-2);

  span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}

.app-select__option--active {
  background: var(--color-row-hover);
  color: var(--color-text);
}

.app-select__option--selected {
  background: var(--color-active-soft);
  color: var(--color-active);
  font-weight: var(--font-weight-semibold);
}

.app-select-menu-enter-active,
.app-select-menu-leave-active {
  transition:
    opacity var(--transition-fast),
    transform var(--transition-fast);
}

.app-select-menu-enter-from,
.app-select-menu-leave-to {
  opacity: 0;
  transform: translateY(-0.25rem) scale(0.98);
}
</style>
