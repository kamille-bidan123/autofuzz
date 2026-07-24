<script setup>
import { X } from '@lucide/vue';
import { useAutofuzz } from '../appContext';
import PathPicker from './PathPicker.vue';

const ui = useAutofuzz();
</script>

<template>
  <div v-if="ui.createModalOpen" class="modal" @click.self="ui.closeCreateModal">
    <section class="modal-card" role="dialog" aria-modal="true" aria-labelledby="createModalTitle">
      <div class="modal-head">
        <h2 id="createModalTitle">创建 Task</h2>
        <button class="modal-close icon-button" type="button" aria-label="关闭" @click="ui.closeCreateModal"><X :size="20" /></button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="ui.submitCreateTask">
          <div class="form-grid">
            <div class="field full"><label for="repository_url">本地目录或 Git 仓库 *</label><PathPicker id="repository_url" v-model="ui.createForm.values.repository_url" required placeholder="/path/to/library 或 https://..." :state="ui.pathPickerState('repository_url')" @input-change="ui.onPathInput('repository_url')" @toggle="ui.togglePathPicker('repository_url')" @close="ui.closePathPickers()" @select-current="ui.selectCurrentPath('repository_url')" @select-entry="ui.selectPathEntry('repository_url', $event)" @open-dir="ui.openPathPicker('repository_url', $event)" /></div>
            <div class="field full"><label for="promefuzz">PromeFuzz 路径 *</label><PathPicker id="promefuzz" v-model="ui.createForm.values.promefuzz" required :state="ui.pathPickerState('promefuzz')" @input-change="ui.onPathInput('promefuzz')" @toggle="ui.togglePathPicker('promefuzz')" @close="ui.closePathPickers()" @select-current="ui.selectCurrentPath('promefuzz')" @select-entry="ui.selectPathEntry('promefuzz', $event)" @open-dir="ui.openPathPicker('promefuzz', $event)" /></div>
          </div>
          <details class="advanced-section">
            <summary class="advanced-summary">高级参数</summary>
            <div class="form-grid">
              <div class="field"><label for="ref">Git ref / tag / branch</label><input id="ref" v-model="ui.createForm.values.ref" placeholder="可选"></div>
              <div class="field"><label for="workspace">工作目录</label><PathPicker id="workspace" v-model="ui.createForm.values.workspace" required :state="ui.pathPickerState('workspace')" @input-change="ui.onPathInput('workspace')" @toggle="ui.togglePathPicker('workspace')" @close="ui.closePathPickers()" @select-current="ui.selectCurrentPath('workspace')" @select-entry="ui.selectPathEntry('workspace', $event)" @open-dir="ui.openPathPicker('workspace', $event)" /></div>
              <div class="field full"><label for="promefuzz_config">PromeFuzz config.toml</label><PathPicker id="promefuzz_config" v-model="ui.createForm.values.promefuzz_config" :state="ui.pathPickerState('promefuzz_config')" @input-change="ui.onPathInput('promefuzz_config')" @toggle="ui.togglePathPicker('promefuzz_config')" @close="ui.closePathPickers()" @select-current="ui.selectCurrentPath('promefuzz_config')" @select-entry="ui.selectPathEntry('promefuzz_config', $event)" @open-dir="ui.openPathPicker('promefuzz_config', $event)" /></div>
              <div class="field full"><label for="python">虚拟环境 Python</label><PathPicker id="python" v-model="ui.createForm.values.python" :state="ui.pathPickerState('python')" @input-change="ui.onPathInput('python')" @toggle="ui.togglePathPicker('python')" @close="ui.closePathPickers()" @select-current="ui.selectCurrentPath('python')" @select-entry="ui.selectPathEntry('python', $event)" @open-dir="ui.openPathPicker('python', $event)" /></div>
              <div class="field"><label for="jobs">构建并行度</label><input id="jobs" v-model.number="ui.createForm.values.jobs" type="number" min="1" required></div>
              <div class="field"><label for="pool_size">PromeFuzz 并发度</label><input id="pool_size" v-model.number="ui.createForm.values.pool_size" type="number" min="1" required></div>
              <div class="field"><label for="max_fuzz_drivers">Fuzz driver 并发上限</label><input id="max_fuzz_drivers" v-model.number="ui.createForm.values.max_fuzz_drivers" type="number" min="1" required></div>
              <div class="field"><label for="stop_after">停止阶段</label><select id="stop_after" v-model="ui.createForm.values.stop_after"><option value="built">built</option><option value="configured">configured</option><option value="preprocessed">preprocessed</option><option value="comprehended">comprehended</option><option value="generated">generated</option><option value="fuzzing">fuzzing</option></select></div>
              <div class="field full"><label for="codex_command">Codex CLI 命令</label><PathPicker id="codex_command" v-model="ui.createForm.values.codex_command" required :state="ui.pathPickerState('codex_command')" @input-change="ui.onPathInput('codex_command')" @toggle="ui.togglePathPicker('codex_command')" @close="ui.closePathPickers()" @select-current="ui.selectCurrentPath('codex_command')" @select-entry="ui.selectPathEntry('codex_command', $event)" @open-dir="ui.openPathPicker('codex_command', $event)" /></div>
              <div class="field"><label for="codex_model">Codex 模型</label><input id="codex_model" v-model="ui.createForm.values.codex_model" placeholder="默认模型"></div>
              <div class="field"><label for="codex_profile">Codex profile</label><input id="codex_profile" v-model="ui.createForm.values.codex_profile" placeholder="可选"></div>
              <div class="checks"><label class="check"><input v-model="ui.createForm.values.resume" type="checkbox">从已有状态恢复</label><label class="check"><input v-model="ui.createForm.values.verbose" type="checkbox">服务端同步输出日志</label></div>
            </div>
          </details>
          <div class="modal-actions">
            <button type="button" @click="ui.closeCreateModal">取消</button>
            <button class="primary" type="submit" :disabled="ui.createForm.submitting">{{ ui.createForm.submitting ? '创建中...' : '创建 Task' }}</button>
          </div>
          <div v-if="ui.createForm.message" class="notice" role="status">{{ ui.createForm.message }}</div>
        </form>
      </div>
    </section>
  </div>
</template>
