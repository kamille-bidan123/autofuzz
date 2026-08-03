<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Activity, ClipboardList, ListTodo, RadioTower } from '@lucide/vue';

const loading = ref(true);
const error = ref('');
const queue = ref({
  generated_at: '',
  summary: {
    total: 0,
    queued: 0,
    running: 0,
    refresh: 0,
    required: 0,
    snapshots: 0,
    branch_reach: 0
  },
  items: []
});

let pollTimer = 0;

const summary = computed(() => queue.value.summary || {});
const items = computed(() => Array.isArray(queue.value.items) ? queue.value.items : []);
const runningItems = computed(() => items.value.filter(item => item.status === 'running'));
const queuedItems = computed(() => items.value.filter(item => item.status === 'queued'));

function formatTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function taskLabel(item) {
  if (item.task_name && item.task_id) return `${item.task_name} · ${item.task_id}`;
  return item.task_name || item.task_id || '未关联任务';
}

function driverLabel(item) {
  if (item.driver_id) {
    return item.seq ? `d${item.driver_id}/v${item.seq}` : `d${item.driver_id}`;
  }
  if (item.seq) return `v${item.seq}`;
  return '-';
}

function pathRows(item) {
  return [
    item.snapshot_dir ? {label: 'Snapshot', value: item.snapshot_dir} : null,
    item.profdata_path ? {label: 'Profdata', value: item.profdata_path} : null,
    item.binary_path ? {label: 'Binary', value: item.binary_path} : null
  ].filter(Boolean);
}

async function loadQueue() {
  try {
    const response = await fetch('/api/coverage-queue');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '覆盖队列读取失败');
    queue.value = {
      generated_at: data.generated_at || '',
      summary: data.summary || queue.value.summary,
      items: Array.isArray(data.items) ? data.items : []
    };
    error.value = '';
  } catch (err) {
    error.value = err.message || '覆盖队列读取失败';
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  loadQueue();
  pollTimer = window.setInterval(loadQueue, 3000);
});

onUnmounted(() => {
  if (pollTimer) window.clearInterval(pollTimer);
});
</script>

<template>
  <div class="page-view coverage-queue-view">
    <div v-if="error" class="inline-alert" role="status">{{ error }}</div>

    <section class="dashboard-kpis" aria-label="llvm-cov 队列汇总">
      <article class="kpi-card">
        <div class="kpi-card-top">
          <span class="kpi-label"><ClipboardList :size="15" aria-hidden="true" />总请求</span>
          <span class="kpi-icon"><ClipboardList :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ summary.total || 0 }}</strong>
        <em>{{ queue.generated_at ? `更新于 ${formatTime(queue.generated_at)}` : '等待第一次采集' }}</em>
      </article>
      <article class="kpi-card accent">
        <div class="kpi-card-top">
          <span class="kpi-label"><Activity :size="15" aria-hidden="true" />执行中</span>
          <span class="kpi-icon"><Activity :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ summary.running || 0 }}</strong>
        <em>同一时间只允许 1 个 llvm-cov</em>
      </article>
      <article class="kpi-card warn">
        <div class="kpi-card-top">
          <span class="kpi-label"><ListTodo :size="15" aria-hidden="true" />排队中</span>
          <span class="kpi-icon"><ListTodo :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ summary.queued || 0 }}</strong>
        <em>前台等待 {{ summary.required || 0 }} · 后台刷新 {{ summary.refresh || 0 }}</em>
      </article>
      <article class="kpi-card danger">
        <div class="kpi-card-top">
          <span class="kpi-label"><RadioTower :size="15" aria-hidden="true" />Proof 校验</span>
          <span class="kpi-icon"><RadioTower :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ summary.branch_reach || 0 }}</strong>
        <em>覆盖快照 {{ summary.snapshots || 0 }} · Proof 校验 {{ summary.branch_reach || 0 }}</em>
      </article>
    </section>

    <div class="coverage-queue-grid">
      <section class="panel">
        <div class="panel-head compact">
          <div>
            <h2>当前执行</h2>
            <p>后台唯一允许并发的 llvm-cov 请求</p>
          </div>
          <span class="panel-meta">{{ runningItems.length }} 条</span>
        </div>
        <div class="coverage-queue-stack">
          <div v-if="loading && !items.length" class="dashboard-empty">正在读取全局覆盖队列...</div>
          <div v-else-if="!runningItems.length" class="dashboard-empty">当前没有正在执行的 llvm-cov 请求。</div>
          <article v-for="item in runningItems" :key="item.id" class="coverage-queue-card running">
            <div class="coverage-queue-card-head">
              <div>
                <strong>{{ item.kind_label }}</strong>
                <p>{{ item.mode_label }} · 正在执行</p>
              </div>
              <span class="queue-status-pill running">执行中</span>
            </div>
            <div class="coverage-queue-facts">
              <div><span>任务</span><strong>{{ taskLabel(item) }}</strong></div>
              <div><span>Driver</span><strong>{{ driverLabel(item) }}</strong></div>
              <div><span>阶段</span><strong>{{ item.current_stage || '-' }}</strong></div>
              <div><span>入队时间</span><strong>{{ formatTime(item.queued_at) }}</strong></div>
              <div><span>开始时间</span><strong>{{ formatTime(item.started_at) }}</strong></div>
              <div><span>合并请求</span><strong>{{ item.coalesced || 1 }}</strong></div>
            </div>
            <div class="coverage-queue-paths">
              <div v-for="row in pathRows(item)" :key="`${item.id}:${row.label}`" class="coverage-queue-path">
                <span>{{ row.label }}</span>
                <code>{{ row.value }}</code>
              </div>
            </div>
          </article>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head compact">
          <div>
            <h2>等待队列</h2>
            <p>后续将按顺序执行，refresh 请求会按 key 合并</p>
          </div>
          <span class="panel-meta">{{ queuedItems.length }} 条</span>
        </div>
        <div class="coverage-queue-stack">
          <div v-if="loading && !items.length" class="dashboard-empty">正在读取全局覆盖队列...</div>
          <div v-else-if="!queuedItems.length" class="dashboard-empty">当前没有排队中的 llvm-cov 请求。</div>
          <article v-for="item in queuedItems" :key="item.id" class="coverage-queue-card">
            <div class="coverage-queue-card-head">
              <div>
                <strong>{{ item.kind_label }}</strong>
                <p>{{ item.mode_label }} · 队列位置 {{ item.position || '-' }}</p>
              </div>
              <span class="queue-status-pill">{{ item.status === 'queued' ? `排队 #${item.position || '-'}` : item.status }}</span>
            </div>
            <div class="coverage-queue-facts">
              <div><span>任务</span><strong>{{ taskLabel(item) }}</strong></div>
              <div><span>Driver</span><strong>{{ driverLabel(item) }}</strong></div>
              <div><span>阶段</span><strong>{{ item.current_stage || '-' }}</strong></div>
              <div><span>入队时间</span><strong>{{ formatTime(item.queued_at) }}</strong></div>
              <div><span>模式</span><strong>{{ item.mode_label }}</strong></div>
              <div><span>合并请求</span><strong>{{ item.coalesced || 1 }}</strong></div>
            </div>
            <div class="coverage-queue-paths">
              <div v-for="row in pathRows(item)" :key="`${item.id}:${row.label}`" class="coverage-queue-path">
                <span>{{ row.label }}</span>
                <code>{{ row.value }}</code>
              </div>
            </div>
          </article>
        </div>
      </section>
    </div>
  </div>
</template>
