<script setup>
import { Funnel } from '@lucide/vue';
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <div class="detail-tab-stack">
    <section v-if="ui.sortedCrashQueue.length" class="panel">
      <div class="panel-head compact"><div><h2>分析队列</h2><p>{{ ui.sortedCrashQueue.length }} 个 crash 等待或正在分析</p></div></div>
      <div class="crash-queue-list">
        <div class="crash-queue-row head"><div>driver</div><div>版本</div><div>crash</div><div>状态</div><div>时间</div><div>操作</div></div>
        <div v-for="item in ui.sortedCrashQueue" :key="item.id || `${item.driver_id}:${item.seq}:${item.file}`" class="crash-queue-row" :class="item.status">
          <div>{{ ui.queueDriverLabel(item) }}</div>
          <div>v{{ item.seq || '-' }}</div>
          <div class="crash-queue-task">{{ item.file || '(unknown)' }}<template v-if="item.type"> · {{ item.type }}</template></div>
          <div><span class="crash-queue-status"><span v-if="item.status === 'running'" class="crash-queue-spinner"></span>{{ item.status === 'running' ? '正在分析' : '排队中' }}</span></div>
          <div>{{ ui.shortTime(item.status === 'running' ? item.started_at : item.queued_at) }}</div>
          <div><button class="driver-detail-button danger-mini" type="button" :disabled="!item.removable || ui.isCrashQueueBusy(item.id)" @click="ui.removeCrashQueueItem(item.id)">移出</button></div>
        </div>
      </div>
    </section>

    <section id="uniqueCrashPanel" class="panel">
      <div class="panel-head compact">
        <div><h2>Unique Crash</h2><p>跨 snapshot 去重后的问题列表</p></div>
        <div class="unique-crash-tools">
          <button
            v-if="!ui.crashFixMode"
            class="driver-detail-button"
            type="button"
            :disabled="ui.uniqueCrashRepairableCount === 0"
            @click="ui.toggleCrashFixMode"
          >修复 crash 生成新 task</button>
          <template v-else>
            <span class="selection-note">{{ ui.crashFixSelectionCount }} 已选</span>
            <button class="task-action primary" type="button" :disabled="ui.crashFixBusy || ui.crashFixSelectionCount === 0" @click="ui.submitCrashFixTask">
              {{ ui.crashFixBusy ? '修复中...' : '修复' }}
            </button>
            <button class="task-action" type="button" :disabled="ui.crashFixBusy" @click="ui.cancelCrashFixSelection">取消</button>
          </template>
        </div>
      </div>
      <div v-if="ui.crashFixMessage" class="inline-alert crash-fix-alert" role="status">{{ ui.crashFixMessage }}</div>
      <div class="unique-crash-list">
        <div v-if="!ui.uniqueCrashTotalCount" class="cov-empty">尚未发现 unique crash</div>
        <template v-else>
          <div class="unique-crash-row head" :class="{selecting: ui.crashFixMode}">
            <div v-if="ui.crashFixMode">选择</div>
            <div>driver</div>
            <div>版本</div>
            <div class="unique-crash-filter-cell">
              <span>crash</span>
              <button
                type="button"
                class="table-filter-button"
                :class="{active: ui.uniqueCrashFilterActive('crash')}"
                title="按 crash 文件名类型过滤"
                @click.stop="ui.toggleUniqueCrashFilter('crash')"
              ><Funnel :size="12" aria-hidden="true" /><span>{{ ui.uniqueCrashFilterSummary('crash') }}</span></button>
              <div v-if="ui.uniqueCrashFilterIsOpen('crash')" class="table-filter-menu" @click.stop @keydown.esc="ui.closeUniqueCrashFilter">
                <label class="table-filter-option all">
                  <input type="checkbox" :checked="ui.uniqueCrashFilterAllSelected('crash')" @change="ui.setUniqueCrashFilterAll('crash', $event.target.checked)">
                  <span>全选</span><em>{{ ui.uniqueCrashFilterSelectedCount('crash') }}/{{ ui.uniqueCrashFilterOptionsFor('crash').length }}</em>
                </label>
                <label v-for="option in ui.uniqueCrashFilterOptionsFor('crash')" :key="option.value" class="table-filter-option">
                  <input type="checkbox" :checked="ui.uniqueCrashFilterOptionChecked('crash', option.value)" @change="ui.setUniqueCrashFilterValue('crash', option.value, $event.target.checked)">
                  <span>{{ option.label }}</span><em>{{ option.count }}</em>
                </label>
              </div>
            </div>
            <div class="unique-crash-filter-cell">
              <span>状态</span>
              <button
                type="button"
                class="table-filter-button"
                :class="{active: ui.uniqueCrashFilterActive('status')}"
                title="按分析状态过滤"
                @click.stop="ui.toggleUniqueCrashFilter('status')"
              ><Funnel :size="12" aria-hidden="true" /><span>{{ ui.uniqueCrashFilterSummary('status') }}</span></button>
              <div v-if="ui.uniqueCrashFilterIsOpen('status')" class="table-filter-menu" @click.stop @keydown.esc="ui.closeUniqueCrashFilter">
                <label class="table-filter-option all">
                  <input type="checkbox" :checked="ui.uniqueCrashFilterAllSelected('status')" @change="ui.setUniqueCrashFilterAll('status', $event.target.checked)">
                  <span>全选</span><em>{{ ui.uniqueCrashFilterSelectedCount('status') }}/{{ ui.uniqueCrashFilterOptionsFor('status').length }}</em>
                </label>
                <label v-for="option in ui.uniqueCrashFilterOptionsFor('status')" :key="option.value" class="table-filter-option">
                  <input type="checkbox" :checked="ui.uniqueCrashFilterOptionChecked('status', option.value)" @change="ui.setUniqueCrashFilterValue('status', option.value, $event.target.checked)">
                  <span>{{ option.label }}</span><em>{{ option.count }}</em>
                </label>
              </div>
            </div>
            <div class="unique-crash-filter-cell">
              <span>类型</span>
              <button
                type="button"
                class="table-filter-button"
                :class="{active: ui.uniqueCrashFilterActive('type')}"
                title="按 crash 类型过滤"
                @click.stop="ui.toggleUniqueCrashFilter('type')"
              ><Funnel :size="12" aria-hidden="true" /><span>{{ ui.uniqueCrashFilterSummary('type') }}</span></button>
              <div v-if="ui.uniqueCrashFilterIsOpen('type')" class="table-filter-menu" @click.stop @keydown.esc="ui.closeUniqueCrashFilter">
                <label class="table-filter-option all">
                  <input type="checkbox" :checked="ui.uniqueCrashFilterAllSelected('type')" @change="ui.setUniqueCrashFilterAll('type', $event.target.checked)">
                  <span>全选</span><em>{{ ui.uniqueCrashFilterSelectedCount('type') }}/{{ ui.uniqueCrashFilterOptionsFor('type').length }}</em>
                </label>
                <label v-for="option in ui.uniqueCrashFilterOptionsFor('type')" :key="option.value" class="table-filter-option">
                  <input type="checkbox" :checked="ui.uniqueCrashFilterOptionChecked('type', option.value)" @change="ui.setUniqueCrashFilterValue('type', option.value, $event.target.checked)">
                  <span>{{ option.label }}</span><em>{{ option.count }}</em>
                </label>
              </div>
            </div>
            <div>生成时间</div>
            <div>上次分析</div>
            <div>操作</div>
          </div>
          <div v-if="!ui.uniqueCrashItems.length" class="cov-empty">当前筛选没有匹配的 unique crash</div>
          <div
            v-for="item in ui.uniqueCrashItems"
            :key="ui.uniqueCrashKey(item)"
            class="unique-crash-row"
            :class="{selecting: ui.crashFixMode, 'fix-disabled': ui.crashFixMode && !ui.canSelectCrashFix(item)}"
            :title="ui.crashFixMode ? ui.crashFixDisabledReason(item) : ''"
          >
            <label v-if="ui.crashFixMode" class="crash-select-cell" @click.stop>
              <input
                type="checkbox"
                :checked="ui.isCrashFixSelected(item)"
                :disabled="!ui.canSelectCrashFix(item)"
                :aria-label="`选择 ${ui.uniqueCrashEntry(item).file || 'crash'}`"
                @change="ui.setCrashFixSelected(item, $event.target.checked)"
              >
            </label>
            <div>{{ ui.uniqueCrashDriverLabel(item) }}</div>
            <div>v{{ item.seq || '-' }}</div>
            <div class="unique-crash-name">{{ ui.uniqueCrashEntry(item).file || '(unknown)' }}</div>
            <div><span class="crash-class" :class="ui.crashBadgeForEntry(ui.uniqueCrashEntry(item)).className">{{ ui.crashBadgeForEntry(ui.uniqueCrashEntry(item)).label }}</span></div>
            <div>{{ ui.uniqueCrashEntry(item).type || '-' }}</div>
            <div class="unique-crash-time">{{ ui.uniqueCrashCreatedAt(item) }}</div>
            <div class="unique-crash-time">{{ ui.uniqueCrashLastAnalysisAt(item) }}</div>
            <div class="unique-crash-actions">
              <button type="button" class="driver-detail-button" @click="ui.openUniqueCrash(item)">查看</button>
              <button type="button" class="driver-detail-button" :disabled="!ui.canAnalyzeUniqueCrash(item)" @click="ui.analyzeUniqueCrash(item)">{{ ui.uniqueCrashAnalyzeLabel(item) }}</button>
            </div>
          </div>
        </template>
      </div>
    </section>
  </div>
</template>
