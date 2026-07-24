<script setup>
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <section class="panel">
    <div class="panel-head compact"><div><h2>执行阶段</h2><p>Fuzz 与 LLM 优化循环</p></div></div>
    <div class="stage-scroll">
      <div class="stages">
        <template v-for="stage in ui.linearStages" :key="stage.id">
          <div class="stage linear-stage" :class="stage.status" :data-stage="stage.id" :data-owner="stage.owner">
            <div class="stage-top"><span class="stage-index">{{ stage.index }}</span><span class="spinner"></span></div>
            <div class="stage-name">{{ stage.name }}</div>
            <span class="stage-owner">{{ stage.owner }}</span>
          </div>
          <div class="flow-connector" aria-hidden="true"></div>
        </template>
        <div class="stage-cycle">
          <div class="stage" :class="ui.fuzzStage.status" data-stage="fuzzing" :data-owner="ui.fuzzStage.owner">
            <div class="stage-top"><span class="stage-index">7</span><span class="spinner"></span></div>
            <div class="stage-name">{{ ui.fuzzStage.name }}</div>
            <span class="stage-owner">{{ ui.fuzzStage.owner }}</span>
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
          <div class="stage" :class="ui.analysisStage.status" data-stage="fuzz_analysis" :data-owner="ui.analysisStage.owner">
            <div class="stage-top"><span class="stage-index">↻</span><span class="spinner"></span></div>
            <div class="stage-name">{{ ui.analysisStage.name }}</div>
            <span class="stage-owner">{{ ui.analysisStage.owner }}</span>
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
</template>
