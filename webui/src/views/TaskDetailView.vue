<script setup>
import { ArrowLeft, FileCode, Play, Square, WandSparkles } from '@lucide/vue';
import { useAutofuzz } from '../appContext';
import OverviewTab from './task-tabs/OverviewTab.vue';
import CoverageTab from './task-tabs/CoverageTab.vue';
import CrashesTab from './task-tabs/CrashesTab.vue';
import SnapshotsTab from './task-tabs/SnapshotsTab.vue';
import CodexTab from './task-tabs/CodexTab.vue';
import LogsTab from './task-tabs/LogsTab.vue';
import SnapshotDiffView from './task-tabs/SnapshotDiffView.vue';
import CrashReportView from './task-tabs/CrashReportView.vue';
import DriverCoverageView from './task-tabs/DriverCoverageView.vue';
import LibraryConfigView from './task-tabs/LibraryConfigView.vue';

const ui = useAutofuzz();
</script>

<template>
  <div class="page-view task-detail-view">
    <div class="detail-toolbar">
      <button class="back-button icon-text-button" type="button" @click="ui.navigate('tasks')">
        <ArrowLeft :size="16" />
        <span>任务列表</span>
      </button>
      <div class="detail-identity">
        <span class="run-status" :class="ui.statusClass(ui.detail.status)">{{ ui.detail.statusText }}</span>
        <span v-if="ui.detail.taskKind === 'crash_fix_child'" class="detail-kind">
          修复子任务 · d{{ ui.detail.originDriverId || '-' }}/v{{ ui.detail.originDriverSeq || '-' }}
        </span>
        <span class="detail-repo" :title="ui.detail.repo">{{ ui.detail.repo }}</span>
      </div>
      <div class="detail-actions">
        <button v-if="ui.detailResumable" class="primary icon-text-button" type="button" :disabled="ui.detailActionBusy.resume" @click="ui.resumeTask">
          <Play :size="15" /><span>恢复</span>
        </button>
        <button class="danger icon-text-button" type="button" :disabled="ui.detail.status !== 'running' || ui.detailActionBusy.cancel" @click="ui.cancelTask">
          <Square :size="14" /><span>停止</span>
        </button>
        <button class="debug icon-text-button" type="button" :disabled="!ui.canTriggerFuzz" title="手动触发 LLM 分析优化" @click="ui.triggerFuzz">
          <WandSparkles :size="15" /><span>触发分析</span>
        </button>
        <button class="driver-detail-button icon-text-button" type="button" :disabled="!ui.canOpenLibraryConfig" title="查看或修改 library.toml" @click="ui.openLibraryConfig">
          <FileCode :size="15" /><span>library.toml</span>
        </button>
      </div>
    </div>

    <div v-if="ui.detail.message" class="inline-alert" role="status">{{ ui.detail.message }}</div>

    <div class="detail-tabs" role="tablist" aria-label="任务详情">
      <button
        v-for="tab in ui.detailTabs"
        :key="tab.id"
        class="detail-tab"
        :class="{active: ui.detail.activeTab === tab.id}"
        type="button"
        role="tab"
        :aria-selected="ui.detail.activeTab === tab.id"
        @click="ui.setDetailTab(tab.id)"
      >{{ tab.label }}</button>
    </div>

    <DriverCoverageView v-if="ui.detail.coverageDetail.visible" />
    <SnapshotDiffView v-else-if="ui.detail.snapshotDiff.visible" />
    <CrashReportView v-else-if="ui.detail.crashReport.visible" />
    <LibraryConfigView v-else-if="ui.detail.libraryConfig.visible" />
    <OverviewTab v-else-if="ui.detail.activeTab === 'overview'" />
    <CoverageTab v-else-if="ui.detail.activeTab === 'coverage'" />
    <CrashesTab v-else-if="ui.detail.activeTab === 'crashes'" />
    <SnapshotsTab v-else-if="ui.detail.activeTab === 'snapshots'" />
    <CodexTab v-else-if="ui.detail.activeTab === 'codex'" />
    <LogsTab v-else />
  </div>
</template>
