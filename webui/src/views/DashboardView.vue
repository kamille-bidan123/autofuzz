<script setup>
import { Activity, AlertTriangle, ArrowRight, ClipboardList, RadioTower } from '@lucide/vue';
import { useAutofuzz } from '../appContext';

const ui = useAutofuzz();
</script>

<template>
  <div class="page-view dashboard-view">
    <div v-if="ui.messages.dashboard" class="inline-alert" role="status">{{ ui.messages.dashboard }}</div>

    <section v-if="ui.tasksLoading && !ui.taskCounts.total" class="dashboard-kpis" aria-label="正在加载运行指标" aria-busy="true">
      <article v-for="index in 4" :key="index" class="kpi-card skeleton-card"><span></span><strong></strong><em></em></article>
    </section>
    <section v-else class="dashboard-kpis" aria-label="运行指标">
      <article class="kpi-card">
        <div class="kpi-card-top">
          <span class="kpi-label"><ClipboardList :size="15" aria-hidden="true" />总任务</span>
          <span class="kpi-icon"><ClipboardList :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ ui.taskCounts.total }}</strong>
        <em>{{ ui.totalTaskNote }}</em>
      </article>
      <article class="kpi-card accent">
        <div class="kpi-card-top">
          <span class="kpi-label"><RadioTower :size="15" aria-hidden="true" />运行中</span>
          <span class="kpi-icon"><RadioTower :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ ui.runningTasks }}</strong>
        <em>执行中或停止中</em>
      </article>
      <article class="kpi-card warn">
        <div class="kpi-card-top">
          <span class="kpi-label"><AlertTriangle :size="15" aria-hidden="true" />发现问题</span>
          <span class="kpi-icon"><AlertTriangle :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ ui.discoveredIssues }}</strong>
        <em>{{ ui.issueNote }}</em>
      </article>
      <article class="kpi-card danger">
        <div class="kpi-card-top">
          <span class="kpi-label"><Activity :size="15" aria-hidden="true" />待分析</span>
          <span class="kpi-icon"><Activity :size="18" aria-hidden="true" /></span>
        </div>
        <strong>{{ ui.queueTotal }}</strong>
        <em>{{ ui.queueNote }}</em>
      </article>
    </section>

    <div class="dashboard-grid">
      <section class="panel">
        <div class="panel-head compact">
          <div><h2>任务状态</h2><p>按生命周期分组</p></div>
          <button class="text-button icon-text-button" type="button" @click="ui.navigate('tasks')">查看全部<ArrowRight :size="14" aria-hidden="true" /></button>
        </div>
        <div class="status-board">
          <section v-for="column in ui.statusColumns" :key="column.label" class="status-column">
            <div class="status-column-head">
              <span class="status-column-title"><i class="status-column-dot" aria-hidden="true"></i>{{ column.label }}</span>
              <span class="status-column-count">{{ column.tasks.length }}</span>
            </div>
            <button
              v-for="task in column.tasks.slice(0, 4)"
              :key="task.id"
              class="status-task"
              type="button"
              @click="ui.openTask(task.id)"
            >
              <strong>{{ task.name || task.id }}</strong>
              <span class="status-task-meta">{{ task.current_stage || ui.statusLabel(task.status) || '-' }}</span>
            </button>
            <button v-if="column.tasks.length > 4" class="column-more" type="button" @click="ui.navigate('tasks')">
              还有 {{ column.tasks.length - 4 }} 个
            </button>
            <div v-if="column.tasks.length === 0" class="column-empty">暂无</div>
          </section>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head compact">
          <div><h2>最近发现</h2><p>所有任务的 unique crash</p></div>
        </div>
        <div class="dashboard-list issue-list">
          <div v-if="ui.recentIssues.length === 0" class="dashboard-empty">暂无 unique crash</div>
          <button
            v-for="issue in ui.recentIssues"
            :key="ui.issueKey(issue)"
            class="dashboard-row"
            type="button"
            @click="ui.openIssue(issue)"
          >
            <div class="dashboard-row-head">
              <div class="dashboard-row-main">
                <strong>{{ issue.file || '(unknown crash)' }}</strong>
                <p>{{ issue.task_name || issue.task_id || '-' }} · {{ ui.issueDriverLabel(issue) }} · {{ issue.type || '-' }}</p>
              </div>
              <span class="crash-class" :class="ui.crashBadge(issue).className">{{ ui.crashBadge(issue).label }}</span>
            </div>
          </button>
        </div>
      </section>
    </div>
  </div>
</template>
