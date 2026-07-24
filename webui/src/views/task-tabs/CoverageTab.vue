<script setup>
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <section class="panel">
    <div class="panel-head compact"><div><h2>覆盖数据</h2><p>任务 union 与子 driver 明细</p></div><span class="panel-meta">{{ ui.coverageTotalMeta }}</span></div>
    <div class="coverage-cards">
      <section class="coverage-card">
        <div class="coverage-card-head"><h3>任务总覆盖</h3></div>
        <div v-if="ui.coverageStats.length" class="cov-summary">
          <div v-for="stat in ui.coverageStats" :key="stat.label" class="cov-stat" :class="stat.cls">
            <div class="num">{{ stat.num }}</div><div class="lbl">{{ stat.label }}</div>
          </div>
        </div>
        <div class="cov-list">
          <div v-if="!ui.coverageData || !ui.coverageData.timestamp" class="cov-empty">覆盖数据将在 fuzzing 阶段开始后可用</div>
          <div v-else-if="!ui.coverageData.available" class="cov-empty">等待 corpus monitor 采集覆盖数据...</div>
          <div v-else-if="!ui.coveragePartials.length" class="cov-empty">所有已执行函数均为完全覆盖</div>
          <details v-for="fn in ui.coveragePartials" v-else :key="`${fn.file}:${fn.function}:${fn.start_line}`" class="cov-fn">
            <summary><span class="fn-name">{{ fn.function }}</span><span class="fn-meta">{{ fn.meta }}</span><span class="fn-badge">{{ fn.branchCount }} 条未覆盖</span></summary>
            <div class="cov-branches">
              <div v-for="(branch, index) in fn.uncovered_branches || []" :key="index" class="cov-branch">
                <span class="br-line">{{ ui.coverageBranchLine(branch) }}</span>
                <div class="br-cond">{{ branch.condition || '(unknown condition)' }}</div>
                <div class="br-meta">
                  <span v-if="branch.missing" class="br-missing">缺失: {{ branch.missing }}</span>
                  <span v-if="branch.counts" class="br-counts">{{ ui.branchCountsText(branch) }}</span>
                </div>
              </div>
            </div>
          </details>
        </div>
      </section>

      <section v-if="ui.coverageIsMulti" class="coverage-card">
        <div class="coverage-card-head"><h3>子 driver</h3><span>{{ ui.coverageDriverMeta }}</span></div>
        <div class="driver-cov-list">
          <div v-if="!ui.coverageTargets.length" class="cov-empty">等待 multi-driver 调度数据</div>
          <template v-else>
            <div class="driver-cov-row head">
              <div v-for="column in ui.driverColumns" :key="column.id" class="driver-th"><span>{{ column.label }}</span><span class="help" :title="column.help" tabindex="0">?</span></div>
            </div>
            <div v-for="target in ui.coverageTargets" :key="`${target.driver_id || 0}:${target.seq || 0}`" class="driver-cov-row" :class="ui.driverRowClass(target)">
              <div class="driver">d{{ target.driver_id || '-' }}</div>
              <div class="status">{{ ui.targetStatusLabel(target.status) }}</div>
              <div>v{{ target.seq || 0 }}</div>
              <div>{{ target.seed_count || 0 }}</div>
              <div>{{ (target.summary || {}).executed_functions || 0 }}</div>
              <div>{{ (target.summary || {}).full_functions || 0 }}</div>
              <div>{{ (target.summary || {}).partial_functions || 0 }}</div>
              <div>{{ target.uncovered_count || 0 }}</div>
              <div><button class="driver-detail-button" type="button" :disabled="!ui.hasDriverCoverageDetails(target)" @click="ui.openDriverCoverage(target.driver_id || 0, target.seq || 0)">查看</button></div>
            </div>
          </template>
        </div>
      </section>
    </div>
  </section>
</template>
