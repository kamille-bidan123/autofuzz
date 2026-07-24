<script setup>
import { onMounted, onUnmounted, ref } from 'vue';
import { File, Folder, FolderOpen } from '@lucide/vue';

const props = defineProps({
  id: {type: String, required: true},
  modelValue: {type: [String, Number], default: ''},
  placeholder: {type: String, default: ''},
  required: {type: Boolean, default: false},
  state: {type: Object, required: true}
});

const emit = defineEmits(['update:modelValue', 'input-change', 'toggle', 'select-current', 'select-entry', 'open-dir', 'close']);
const rootRef = ref(null);
const dropdownRef = ref(null);

function handleInput(event) {
  emit('update:modelValue', event.target.value);
  emit('input-change', event.target.value);
}

function handleKeydown(event) {
  if (event.key === 'Escape') {
    emit('close');
    return;
  }
  if (event.key !== 'ArrowDown' || !props.state.open) return;
  event.preventDefault();
  dropdownRef.value?.querySelector('.pp-item, .pp-current')?.focus();
}

function handleDocumentClick(event) {
  if (!rootRef.value?.contains(event.target)) emit('close');
}

onMounted(() => document.addEventListener('click', handleDocumentClick));
onUnmounted(() => document.removeEventListener('click', handleDocumentClick));
</script>

<template>
  <div ref="rootRef" class="path-picker">
    <input
      :id="id"
      :value="modelValue"
      :required="required"
      :placeholder="placeholder"
      autocomplete="off"
      @input="handleInput"
      @keydown="handleKeydown"
    >
    <button type="button" class="pp-btn icon-button" aria-label="浏览路径" title="浏览路径" @click="emit('toggle')">
      <FolderOpen :size="17" />
    </button>
    <div ref="dropdownRef" class="pp-dropdown" :class="{open: state.open}">
      <div v-if="state.loading" class="pp-empty">读取路径...</div>
      <div v-else-if="state.error" class="pp-empty error-text">{{ state.error }}</div>
      <template v-else>
        <button class="pp-current" type="button" @click="emit('select-current')">
          <Folder :size="16" />
          <span>{{ state.path || '(当前目录)' }}</span>
        </button>
        <div v-if="!(state.entries || []).length" class="pp-empty">空目录</div>
        <button
          v-for="entry in (state.entries || [])"
          :key="entry.path"
          class="pp-item"
          :class="{selected: entry.path === String(modelValue || '').trim()}"
          type="button"
          @click="emit('select-entry', entry)"
          @dblclick="entry.is_dir && emit('open-dir', entry.path)"
        >
          <Folder v-if="entry.is_dir" :size="16" class="pp-icon dir" />
          <File v-else :size="16" class="pp-icon file" />
          <span class="pp-name">{{ entry.name }}</span>
        </button>
      </template>
    </div>
  </div>
</template>
