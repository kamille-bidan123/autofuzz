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
            v-if="!ui.uniqueCrashSelectionMode"
            class="driver-detail-button"
            type="button"
            :disabled="ui.uniqueCrashRepairableCount === 0"
            @click="ui.toggleCrashFixMode"
          >修复 crash 生成新 task</button>
          <button
            v-if="!ui.uniqueCrashSelectionMode"
            class="driver-detail-button danger-mini"
            type="button"
            :disabled="ui.uniqueCrashTotalCount === 0"
            @click="ui.toggleCrashDeleteMode"
          >删除 unique crash</button>
          <template v-else-if="ui.crashFixMode">
            <span class="selection-note">{{ ui.crashFixSelectionCount }} 已选</span>
            <button class="task-action primary" type="button" :disabled="ui.crashFixBusy || ui.crashFixSelectionCount === 0" @click="ui.submitCrashFixTask">
              {{ ui.crashFixBusy ? '修复中...' : '修复' }}
            </button>
            <button class="task-action" type="button" :disabled="ui.crashFixBusy" @click="ui.cancelCrashFixSelection">取消</button>
          </template>
          <template v-else>
            <span class="selection-note">{{ ui.crashDeleteSelectionCount }} 已选</span>
            <button class="task-action danger" type="button" :disabled="ui.crashDeleteBusy || ui.crashDeleteSelectionCount === 0" @click="ui.deleteSelectedUniqueCrashes">
              {{ ui.crashDeleteBusy ? '删除中...' : '删除' }}
            </button>
            <button class="task-action" type="button" :disabled="ui.crashDeleteBusy" @click="ui.cancelCrashDeleteSelection">取消</button>
          </template>
        </div>
      </div>
      <div class="crash-triage-summary">
        <div><span>总数</span><strong>{{ ui.crashTriageSummary.total }}</strong></div>
        <div><span>当前显示</span><strong>{{ ui.crashTriageSummary.visible }}</strong></div>
        <div><span>待分析</span><strong>{{ ui.crashTriageSummary.pending }}</strong></div>
        <div><span>分析中</span><strong>{{ ui.crashTriageSummary.active }}</strong></div>
        <div><span>库问题</span><strong>{{ ui.crashTriageSummary.library }}</strong></div>
        <div><span>可修复</span><strong>{{ ui.crashTriageSummary.fixable }}</strong></div>
      </div>
      <div class="crash-quick-filters" aria-label="Crash 快捷筛选">
        <button
          v-for="option in ui.crashQuickFilterOptions"
          :key="option.id"
          type="button"
          :class="{active: ui.crashQuickFilter === option.id}"
          @click="ui.setCrashQuickFilter(option.id)"
        >
          <span>{{ option.label }}</span>
          <b>{{ option.count }}</b>
        </button>
        <button type="button" class="text-button" @click="ui.resetUniqueCrashFilters">重置过滤</button>
      </div>
      <div class="crash-search-tools">
        <input
          v-model.trim="ui.crashSearchQuery"
          type="search"
          placeholder="搜索 crash、类型、栈、ASan、driver"
          aria-label="搜索 unique crash"
        >
        <label class="filter-control compact-select">
          <span>排序</span>
          <select :value="ui.crashSort" @change="ui.setCrashSort($event.target.value)">
            <option v-for="option in ui.crashSortOptions" :key="option.id" :value="option.id">{{ option.label }}</option>
          </select>
        </label>
      </div>
      <div v-if="ui.crashFixMessage" class="inline-alert crash-fix-alert" role="status">{{ ui.crashFixMessage }}</div>
      <div class="crash-triage-workbench">
        <div class="unique-crash-list">
          <div v-if="!ui.uniqueCrashTotalCount" class="cov-empty">尚未发现 unique crash</div>
          <template v-else>
            <div class="unique-crash-row head" :class="{selecting: ui.uniqueCrashSelectionMode}">
              <div v-if="ui.uniqueCrashSelectionMode">选择</div>
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
              <div>栈签名</div>
              <div>上次分析</div>
              <div>操作</div>
            </div>
            <div v-if="!ui.uniqueCrashItems.length" class="cov-empty">当前筛选没有匹配的 unique crash</div>
            <div
              v-for="item in ui.uniqueCrashItems"
              :key="ui.uniqueCrashKey(item)"
              class="unique-crash-row"
              :class="{selecting: ui.uniqueCrashSelectionMode, selected: ui.uniqueCrashTriagePreview?.item === item, 'fix-disabled': ui.crashFixMode && !ui.canSelectCrashFix(item)}"
              :title="ui.uniqueCrashSelectionDisabledReason(item)"
              @click="ui.selectUniqueCrashPreview(item)"
            >
              <label v-if="ui.uniqueCrashSelectionMode" class="crash-select-cell" @click.stop>
                <input
                  type="checkbox"
                  :checked="ui.isUniqueCrashSelected(item)"
                  :disabled="!ui.canSelectUniqueCrash(item)"
                  :aria-label="`选择 ${ui.uniqueCrashEntry(item).file || 'crash'}`"
                  @change="ui.setUniqueCrashSelected(item, $event.target.checked)"
                >
              </label>
              <div>{{ ui.uniqueCrashDriverLabel(item) }}</div>
              <div>v{{ item.seq || '-' }}</div>
              <div class="unique-crash-name">
                <strong>{{ ui.uniqueCrashEntry(item).file || '(unknown)' }}</strong>
                <span>{{ ui.uniqueCrashCreatedAt(item) }}</span>
              </div>
              <div><span class="crash-class" :class="ui.crashBadgeForEntry(ui.uniqueCrashEntry(item)).className">{{ ui.crashBadgeForEntry(ui.uniqueCrashEntry(item)).label }}</span></div>
              <div>{{ ui.uniqueCrashEntry(item).type || '-' }}</div>
              <div class="unique-crash-stack">{{ ui.uniqueCrashEntry(item).stack || ui.uniqueCrashEntry(item).asan_report || '暂无栈签名' }}</div>
              <div class="unique-crash-time">{{ ui.uniqueCrashLastAnalysisAt(item) }}</div>
              <div class="unique-crash-actions" @click.stop>
                <button type="button" class="driver-detail-button" @click="ui.openUniqueCrash(item)">报告</button>
                <button type="button" class="driver-detail-button" :disabled="!ui.canAnalyzeUniqueCrash(item)" @click="ui.analyzeUniqueCrash(item)">{{ ui.uniqueCrashAnalyzeLabel(item) }}</button>
              </div>
            </div>
          </template>
        </div>

        <aside class="crash-triage-preview">
          <div v-if="!ui.uniqueCrashTriagePreview" class="control-empty">选择一个 unique crash 查看摘要</div>
          <template v-else>
            <div class="crash-preview-head">
              <div>
                <h3>{{ ui.uniqueCrashTriagePreview.file }}</h3>
                <p>{{ ui.uniqueCrashTriagePreview.driver }}/{{ ui.uniqueCrashTriagePreview.version }} · {{ ui.uniqueCrashTriagePreview.type }}</p>
              </div>
              <span class="crash-class" :class="ui.uniqueCrashTriagePreview.badge.className">{{ ui.uniqueCrashTriagePreview.badge.label }}</span>
            </div>
            <div class="crash-preview-facts">
              <div><span>状态</span><strong>{{ ui.uniqueCrashTriagePreview.status }}</strong></div>
              <div><span>分类</span><strong>{{ ui.uniqueCrashTriagePreview.classification }}</strong></div>
              <div><span>发现时间</span><strong>{{ ui.uniqueCrashTriagePreview.createdAt }}</strong></div>
              <div><span>上次分析</span><strong>{{ ui.uniqueCrashTriagePreview.lastAnalysisAt }}</strong></div>
            </div>
            <section class="crash-preview-section">
              <h4>栈签名</h4>
              <pre>{{ ui.uniqueCrashTriagePreview.stack }}</pre>
            </section>
            <section class="crash-preview-section">
              <h4>ASan 摘要</h4>
              <pre>{{ ui.uniqueCrashTriagePreview.asan }}</pre>
            </section>
            <div class="crash-preview-actions">
              <button type="button" class="driver-detail-button" @click="ui.openUniqueCrash(ui.uniqueCrashTriagePreview.item)">查看完整报告</button>
              <button type="button" class="driver-detail-button" :disabled="!ui.canAnalyzeUniqueCrash(ui.uniqueCrashTriagePreview.item)" @click="ui.analyzeUniqueCrash(ui.uniqueCrashTriagePreview.item)">{{ ui.uniqueCrashAnalyzeLabel(ui.uniqueCrashTriagePreview.item) }}</button>
            </div>
          </template>
        </aside>
      </div>
    </section>
  </div>
</template>
