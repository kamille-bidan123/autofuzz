<script setup>
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <div class="detail-tab-stack overview-control">
    <section class="panel overview-stage-panel">
      <div class="panel-head compact"><div><h2>执行阶段</h2><p>Fuzz 与 LLM 优化循环</p></div></div>
      <div class="stage-scroll">
        <div class="stages">
          <template v-for="stage in ui.linearStages" :key="stage.id">
            <div class="stage linear-stage" :class="stage.status" :data-stage="stage.id">
              <div class="stage-top"><span class="stage-index">{{ stage.index }}</span><span class="spinner"></span></div>
              <div class="stage-name">{{ stage.name }}</div>
              <button
                v-if="stage.id === 'configured'"
                class="stage-action-button"
                type="button"
                :disabled="!ui.canOpenLibraryConfig"
                @click.stop="ui.openLibraryConfig"
              >查看配置</button>
            </div>
            <div class="flow-connector" aria-hidden="true"></div>
          </template>
          <div class="stage-cycle">
            <div class="stage" :class="ui.fuzzStage.status" data-stage="fuzzing">
              <div class="stage-top"><span class="stage-index">7</span><span class="spinner"></span></div>
              <div class="stage-name">{{ ui.fuzzStage.name }}</div>
              <div class="stage-detail">{{ ui.fuzzStage.detail }}</div>
            </div>
            <div class="cycle-track" aria-hidden="true">
              <svg class="cycle-svg" viewBox="0 0 132 118">
                <path class="cycle-path cycle-forward" :class="{active: ui.flowForwardActive}" d="M12 48 C32 12 100 12 120 48"></path>
                <polygon class="cycle-head cycle-forward" :class="{active: ui.flowForwardActive}" points="114,41 126,49 113,56"></polygon>
                <text class="cycle-label cycle-forward" :class="{active: ui.flowForwardActive}" x="66" y="17" text-anchor="middle">定时 / 手动</text>
                <path class="cycle-path cycle-back" :class="{active: ui.flowBackActive}" d="M120 70 C100 106 32 106 12 70"></path>
                <polygon class="cycle-head cycle-back" :class="{active: ui.flowBackActive}" points="18,63 6,71 19,78"></polygon>
                <text class="cycle-label cycle-back" :class="{active: ui.flowBackActive}" x="66" y="112" text-anchor="middle">继续 / 重建</text>
              </svg>
            </div>
            <div class="stage" :class="ui.analysisStage.status" data-stage="fuzz_analysis">
              <div class="stage-top"><span class="stage-index">↻</span><span class="spinner"></span></div>
              <div class="stage-name">{{ ui.analysisStage.name }}</div>
              <div class="stage-detail">{{ ui.analysisStage.detail }}</div>
              <div class="stage-result">{{ ui.analysisStage.result }}</div>
            </div>
          </div>
        </div>
      </div>
      <section v-if="ui.driverSchedule" class="driver-schedule">
        <div class="driver-schedule-head">
          <div>
            <h3>子 driver 调度</h3>
            <p>{{ ui.driverSchedule.meta }}<template v-if="ui.driverSchedule.countdown"> · {{ ui.driverSchedule.countdown }}</template></p>
          </div>
          <div class="driver-schedule-legend" aria-label="调度状态图例">
            <span><i class="running"></i>运行中</span>
            <span><i class="next"></i>下一批次</span>
            <span><i class="idle"></i>其他</span>
          </div>
        </div>
        <div v-if="!ui.driverSchedule.items.length" class="driver-schedule-empty">等待子 driver 调度数据</div>
        <div v-else class="driver-schedule-grid">
          <div
            v-for="item in ui.driverSchedule.items"
            :key="item.key"
            class="driver-schedule-tile"
            :class="item.state"
            role="img"
            :aria-label="item.ariaLabel"
            :title="item.ariaLabel"
          >
            <strong>d{{ item.driverId }}</strong>
            <span>v{{ item.seq }}</span>
          </div>
        </div>
      </section>
      <div class="flow-history">
        <div class="flow-history-head"><h3>优化记录</h3><span>{{ ui.flowRows.length }} 轮</span></div>
        <div class="flow-history-list">
          <div v-if="!ui.flowRows.length" class="flow-empty">尚无 LLM 优化分析记录</div>
          <div v-for="row in ui.flowRows" :key="row.iteration" class="flow-row" :class="{failed: row.error}">
            <div><strong>第 {{ row.iteration }} 轮</strong></div>
            <div><span class="flow-tag" :class="{manual: row.trigger === 'manual'}">{{ row.trigger === 'manual' ? '手动' : '定时' }}</span></div>
            <div>{{ row.driver }}</div>
            <div>{{ row.outcome }}</div>
            <div class="flow-summary">{{ row.summary }}</div>
          </div>
        </div>
      </div>
      <div class="meta">{{ ui.detail.meta }}</div>
    </section>

    <section class="panel control-summary-panel">
      <div class="control-summary-strip" aria-label="Task 中控摘要">
        <div v-for="item in ui.taskControlSummaryItems" :key="item.label" class="control-summary-item" :class="item.className">
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
        </div>
      </div>
    </section>

    <div class="control-grid">
      <section class="panel control-panel loop-panel">
        <div class="control-panel-head">
          <div><h3>当前 Loop</h3><p>{{ ui.controlLoopSummary.phase }}</p></div>
          <span class="control-status-pill" :class="ui.controlLoopSummary.statusClass">{{ ui.controlLoopSummary.stage }}</span>
        </div>
        <div class="loop-facts">
          <div><span>运行 driver</span><strong>{{ ui.controlLoopSummary.drivers }}<template v-if="ui.controlLoopSummary.driverOverflow"> +{{ ui.controlLoopSummary.driverOverflow }}</template></strong></div>
          <div><span>下一轮</span><strong>{{ ui.controlLoopSummary.countdown }}</strong></div>
          <div><span>最近结果</span><strong>{{ ui.controlLoopSummary.latest }}</strong></div>
        </div>
        <p class="loop-result">{{ ui.controlLoopSummary.result }}</p>
        <div class="control-actions">
          <button class="driver-detail-button" type="button" @click="ui.setDetailTab('logs')">查看日志</button>
          <button class="driver-detail-button" type="button" @click="ui.setDetailTab('codex')">查看 Codex</button>
        </div>
      </section>

      <section class="panel control-panel driver-board-panel">
        <div class="control-panel-head">
          <div><h3>Driver 状态</h3><p>{{ ui.coverageDriverMeta }}</p></div>
          <button class="driver-detail-button" type="button" @click="ui.setDetailTab('coverage')">查看覆盖</button>
        </div>
        <div v-if="ui.coverageLoading" class="control-empty">正在加载 driver 覆盖数据...</div>
        <div v-else-if="!ui.driverBoardRows.length" class="control-empty">等待子 driver 覆盖数据</div>
        <div v-else class="driver-board-grid">
          <button
            v-for="driver in ui.driverBoardRows"
            :key="driver.key"
            class="driver-board-tile"
            :class="driver.className"
            type="button"
            :disabled="!driver.hasDetails"
            :title="driver.hasDetails ? '查看该 driver 覆盖详情' : '暂无函数覆盖详情'"
            @click="ui.openDriverCoverage(driver.driverId, driver.seq)"
          >
            <div class="driver-board-top">
              <strong>{{ driver.label }}</strong>
              <span>{{ driver.status }}</span>
            </div>
            <div class="driver-board-metrics">
              <span><b>{{ driver.seeds }}</b> seeds</span>
              <span><b>{{ driver.executed }}</b> exec</span>
              <span><b>{{ driver.partial }}</b> partial</span>
              <span><b>{{ driver.uncovered }}</b> branch</span>
              <span><b>{{ driver.apiCount }}</b> API</span>
              <span><b>{{ driver.crashCount }}</b> crash</span>
            </div>
          </button>
        </div>
      </section>

      <section class="panel control-panel coverage-gap-panel">
        <div class="control-panel-head">
          <div><h3>覆盖缺口</h3><p>{{ ui.coverageGapSummary.apiMeta }}</p></div>
          <button class="driver-detail-button" type="button" @click="ui.setDetailTab('coverage')">查看明细</button>
        </div>
        <div class="coverage-gap-stats">
          <div><span>已执行</span><strong>{{ ui.coverageGapSummary.executed }}</strong></div>
          <div><span>完全覆盖</span><strong>{{ ui.coverageGapSummary.full }}</strong></div>
          <div><span>部分覆盖</span><strong>{{ ui.coverageGapSummary.partial }}</strong></div>
          <div><span>未覆盖分支</span><strong>{{ ui.coverageGapSummary.uncoveredBranches }}</strong></div>
        </div>
        <div class="gap-section">
          <div class="gap-section-head"><span>未覆盖 API</span><strong>{{ ui.coverageGapSummary.missingCount }}</strong></div>
          <div v-if="!ui.coverageGapSummary.missingApis.length" class="control-empty slim">{{ ui.coverageLoading ? '正在加载 API 数据...' : '暂无未覆盖导出 API' }}</div>
          <div v-else class="gap-chip-list">
            <span v-for="api in ui.coverageGapSummary.missingApis" :key="`${api.name}:${api.header}`" class="gap-chip" :title="api.headerName">
              {{ api.name }}
            </span>
          </div>
        </div>
        <div class="gap-section">
          <div class="gap-section-head"><span>覆盖最多 driver</span></div>
          <div v-if="!ui.coverageGapSummary.topDrivers.length" class="control-empty slim">等待 driver API 覆盖数据</div>
          <div v-else class="top-driver-list">
            <span v-for="driver in ui.coverageGapSummary.topDrivers" :key="driver.key">
              <b>{{ ui.apiDriverTitle(driver) }}</b>{{ driver.apis.length }} API
            </span>
          </div>
        </div>
      </section>

      <section class="panel control-panel crash-summary-panel">
        <div class="control-panel-head">
          <div><h3>Crash 工作台</h3><p>{{ ui.crashWorkbenchSummary.total }} unique crash · queue {{ ui.crashWorkbenchSummary.queueRunning }}/{{ ui.crashWorkbenchSummary.queuePending }}</p></div>
          <button class="driver-detail-button" type="button" @click="ui.setDetailTab('crashes')">查看 Crash</button>
        </div>
        <div class="crash-summary-stats">
          <div><span>待分析</span><strong>{{ ui.crashWorkbenchSummary.pending }}</strong></div>
          <div><span>分析中</span><strong>{{ ui.crashWorkbenchSummary.running + ui.crashWorkbenchSummary.queued }}</strong></div>
          <div><span>已分类</span><strong>{{ ui.crashWorkbenchSummary.classified }}</strong></div>
          <div><span>可修复</span><strong>{{ ui.crashWorkbenchSummary.fixable }}</strong></div>
        </div>
        <div class="recent-crash-list">
          <div v-if="!ui.crashWorkbenchSummary.recent.length" class="control-empty slim">暂无 unique crash</div>
          <button
            v-for="crash in ui.crashWorkbenchSummary.recent"
            :key="`${crash.driver}:${crash.file}`"
            class="recent-crash-row"
            type="button"
            @click="ui.openUniqueCrash(crash.item)"
          >
            <div><strong>{{ crash.file }}</strong><span>{{ crash.driver }} · {{ crash.type }}</span></div>
            <span class="crash-class" :class="crash.badge.className">{{ crash.badge.label }}</span>
          </button>
        </div>
      </section>
    </div>

  </div>
</template>
