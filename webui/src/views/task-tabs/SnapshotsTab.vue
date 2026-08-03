<script setup>
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <section class="panel">
    <div class="panel-head compact"><div><h2>Driver 版本</h2><p>覆盖变化、Crash 与源码修改历史</p></div></div>
    <div class="snap-table">
      <div v-if="ui.detail.snapshotStatus === 'error'" class="cov-empty error-text">{{ ui.detail.snapshotMessage || 'Snapshot 列表读取失败' }}</div>
      <div v-else-if="ui.detail.snapshotStatus === 'loading' && !ui.snapshotRows.length" class="cov-empty">正在加载 snapshot 缓存...</div>
      <div v-else-if="!ui.snapshotRows.length" class="cov-empty">{{ ui.detail.fuzzStageStatus === 'pending' ? 'fuzzing 阶段开始后可用' : '当前还没有可展示的 snapshot 缓存' }}</div>
      <template v-else>
        <div class="snap-row head" :class="{multi: ui.snapshotsMulti}">
          <div v-if="ui.snapshotsMulti">driver</div><div>v</div><div>时间</div><div>已执行(±)</div><div>未覆盖(±)</div><div>crash</div><div>unique</div><div>报告</div><div>corpus</div><div>LLM 修改</div>
        </div>
        <div v-for="snap in ui.snapshotRows" :key="ui.snapshotKey(snap)" class="snap-row" :class="{multi: ui.snapshotsMulti, clickable: snap.seq > 1}" @click="ui.openSnapshotDiff(snap)">
          <div v-if="ui.snapshotsMulti">d{{ snap.driver_id || '-' }}</div>
          <div><button v-if="snap.seq > 1" type="button" class="snap-version-button" @click.stop="ui.openSnapshotDiff(snap)">v{{ snap.seq }}</button><span v-else>v{{ snap.seq }}</span></div>
          <div>{{ snap.timestamp || '-' }}</div>
          <div>{{ snap.executed_functions || 0 }} <span v-if="snap.seq > 1" class="snap-delta" :class="ui.snapDeltaClass(snap.delta_executed)">{{ ui.snapDeltaStr(snap.delta_executed) }}</span></div>
          <div>{{ snap.uncovered_count || 0 }} <span v-if="snap.seq > 1" class="snap-delta" :class="ui.snapDeltaClass(-(snap.delta_uncovered || 0))">{{ ui.snapDeltaStr(-(snap.delta_uncovered || 0)) }}</span></div>
          <div>{{ snap.crash_count || 0 }}</div>
          <div>{{ snap.unique_crash_count || 0 }}</div>
          <div><button v-if="(snap.unique_crash_count || 0) > 0" type="button" class="crash-report-button" @click.stop="ui.openSnapshotReports(snap)">{{ snap.crash_report_count || 0 }}/{{ snap.unique_crash_count || 0 }}</button><span v-else class="muted">0</span></div>
          <div>{{ snap.corpus_count || 0 }}</div>
          <div class="snap-analysis">{{ snap.analysis || '(无分析)' }}</div>
        </div>
      </template>
    </div>
  </section>
</template>
