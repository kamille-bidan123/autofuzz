<script setup>
import { computed, ref } from 'vue';
import { Search } from '@lucide/vue';
import { useAutofuzz } from '../appContext';

const ui = useAutofuzz();
const query = ref('');
const status = ref('all');

function taskMatches(task) {
  const needle = query.value.trim().toLowerCase();
  if (status.value !== 'all' && task.status !== status.value) return false;
  if (!needle) return true;
  return [task.name, task.id, task.repository_url, task.current_stage, task.parent_task_id]
    .some(value => String(value || '').toLowerCase().includes(needle));
}

function childLabel(task) {
  if (task.task_kind !== 'crash_fix_child') return '';
  const driver = task.origin_driver_id ? `d${task.origin_driver_id}` : 'driver';
  const version = task.origin_driver_seq ? `v${task.origin_driver_seq}` : 'v?';
  return `修复 ${driver}/${version}`;
}

const filteredTasks = computed(() => {
  const visible = new Set(ui.tasks.filter(taskMatches).map(task => task.id));
  const byParent = new Map();
  for (const task of ui.tasks) {
    if (!task.parent_task_id) continue;
    if (!byParent.has(task.parent_task_id)) byParent.set(task.parent_task_id, []);
    byParent.get(task.parent_task_id).push(task);
  }
  const result = [];
  const visited = new Set();
  function pushTask(task, depth) {
    if (!task || visited.has(task.id) || !visible.has(task.id)) return;
    visited.add(task.id);
    result.push({...task, depth, childLabel: childLabel(task)});
    for (const child of byParent.get(task.id) || []) pushTask(child, depth + 1);
  }
  for (const task of ui.tasks) {
    if (task.parent_task_id && visible.has(task.parent_task_id)) continue;
    pushTask(task, 0);
  }
  for (const task of ui.tasks) pushTask(task, 0);
  return result;
});
</script>

<template>
  <div class="page-view">
    <div class="list-toolbar">
      <label class="search-box">
        <Search :size="16" aria-hidden="true" />
        <input v-model="query" type="search" placeholder="搜索任务、仓库或阶段" aria-label="搜索任务">
      </label>
      <label class="filter-control">
        <span>状态</span>
        <select v-model="status">
          <option value="all">全部</option>
          <option value="pending">待启动</option>
          <option value="running">运行中</option>
          <option value="stopping">停止中</option>
          <option value="completed">已完成</option>
          <option value="failed">运行失败</option>
          <option value="interrupted">已中断</option>
          <option value="stopped">已停止</option>
        </select>
      </label>
      <span class="result-count">{{ filteredTasks.length }} / {{ ui.tasks.length }}</span>
    </div>

    <div v-if="ui.messages.list" class="inline-alert" role="status">{{ ui.messages.list }}</div>

    <section class="panel task-list-panel">
      <div class="task-list-head">
        <span>Task</span><span>仓库</span><span>阶段</span><span>状态</span><span>创建时间</span><span class="align-right">操作</span>
      </div>
      <div>
        <div v-if="ui.tasksLoading && !ui.tasks.length" class="task-empty">正在加载任务...</div>
        <div v-else-if="!ui.tasks.length" class="task-empty">暂无 Task，点击右上角创建。</div>
        <div v-else-if="!filteredTasks.length" class="task-empty">没有匹配当前筛选条件的任务。</div>
        <div v-for="task in filteredTasks" :key="task.id" class="task-row" :class="{child: task.depth > 0}" @click="ui.openTask(task.id)">
          <div class="task-name" :style="{paddingLeft: `${Math.min(task.depth || 0, 3) * 22}px`}">
            <span v-if="task.depth > 0" class="task-branch" aria-hidden="true"></span>
            <span>{{ task.name || task.id }}</span>
            <span v-if="task.childLabel" class="task-kind">{{ task.childLabel }}</span>
          </div>
          <div class="task-repo" :title="task.repository_url || ''">{{ task.repository_url || '-' }}</div>
          <div class="task-stage">{{ task.current_stage || '-' }}</div>
          <div><span class="task-badge" :class="ui.statusClass(task.status)">{{ ui.statusLabel(task.status) }}</span></div>
          <div class="task-time">{{ task.created_at ? ui.formatDate(task.created_at) : '-' }}</div>
          <div class="task-actions" @click.stop>
            <button class="task-action danger" type="button" :disabled="ui.isTaskBusy(task.id)" @click="ui.removeTask(task.id)">删除</button>
            <button v-if="task.status === 'pending'" class="task-action primary" type="button" :disabled="ui.isTaskBusy(task.id)" @click="ui.startTask(task.id)">开始</button>
            <button v-if="task.status === 'running'" class="task-action danger" type="button" :disabled="ui.isTaskBusy(task.id)" @click="ui.stopTask(task.id)">停止</button>
            <button v-if="task.status === 'stopping'" class="task-action" type="button" disabled>停止中</button>
            <button v-if="ui.isResumable(task.status)" class="task-action primary" type="button" :disabled="ui.isTaskBusy(task.id)" @click="ui.startTask(task.id)">恢复</button>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>
