<script setup>
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <section class="panel">
    <div class="panel-head compact"><div><h2>覆盖数据</h2><p>任务 union 与子 driver 明细</p></div><span class="panel-meta">{{ ui.coverageTotalMeta }}</span></div>
    <div class="coverage-summary-strip">
      <div v-for="item in ui.coverageSummaryItems" :key="item.label" :class="item.className">
        <span>{{ item.label }}</span>
        <strong>{{ item.value }}</strong>
      </div>
    </div>
    <div class="coverage-cards">
      <section class="coverage-card">
        <div class="coverage-card-head"><h3>任务总覆盖</h3></div>
        <div v-if="ui.coverageStats.length" class="cov-summary">
          <div v-for="stat in ui.coverageStats" :key="stat.label" class="cov-stat" :class="stat.cls">
            <div class="num">{{ stat.num }}</div><div class="lbl">{{ stat.label }}</div>
          </div>
        </div>
        <div class="cov-list">
          <div v-if="ui.coverageLoading" class="cov-empty">正在加载覆盖数据...</div>
          <div v-else-if="ui.coverageError" class="cov-empty error-text">{{ ui.coverageMessage || '覆盖数据读取失败' }}</div>
          <div v-else-if="!ui.coverageData || !ui.coverageData.timestamp" class="cov-empty">覆盖数据将在 fuzzing 阶段开始后可用</div>
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

      <section class="coverage-card api-coverage-card">
        <div class="coverage-card-head api-coverage-head">
          <h3>导出 API 覆盖</h3>
          <div class="api-coverage-head-actions">
            <span>{{ ui.apiCoverageMeta }}</span>
            <div class="segmented-control api-coverage-toggle" role="group" aria-label="导出 API 覆盖视角">
              <button
                type="button"
                :class="{active: ui.apiCoverageView === 'api'}"
                :aria-pressed="ui.apiCoverageView === 'api'"
                @click="ui.setApiCoverageView('api')"
              >按 API</button>
              <button
                type="button"
                :class="{active: ui.apiCoverageView === 'driver'}"
                :aria-pressed="ui.apiCoverageView === 'driver'"
                @click="ui.setApiCoverageView('driver')"
              >按 Driver</button>
            </div>
          </div>
        </div>
        <div class="coverage-toolstrip">
          <input v-model="ui.apiCoverageQuery" type="search" placeholder="搜索 API 或 header" aria-label="搜索导出 API">
          <label class="compact-check" :class="{disabled: ui.apiCoverageView !== 'api'}">
            <input v-model="ui.apiCoverageOnlyMissing" type="checkbox" :disabled="ui.apiCoverageView !== 'api'">
            <span>只看未覆盖 API</span>
          </label>
          <button type="button" class="text-button" @click="ui.resetApiCoverageTools">重置</button>
        </div>
        <div v-if="ui.coverageLoading" class="cov-empty">正在加载 API 覆盖数据...</div>
        <div v-else-if="ui.coverageError" class="cov-empty error-text">{{ ui.coverageMessage || 'API 覆盖数据读取失败' }}</div>
        <div v-else-if="!ui.apiCoverage" class="cov-empty">等待 API 预处理产物</div>
        <div v-else-if="!ui.apiCoverage.available" class="cov-empty">{{ ui.apiCoverage.error || '等待 API 预处理产物' }}</div>
        <div v-else-if="ui.apiCoverageView === 'api'" class="api-coverage-list">
          <div class="api-coverage-row head">
            <div></div>
            <div>API</div>
            <div>子 driver</div>
          </div>
          <div v-if="!ui.apiCoverageVisibleRows.length" class="cov-empty">当前筛选没有匹配的 API</div>
          <div v-for="api in ui.apiCoverageVisibleRows" v-else :key="`${api.name}:${api.decl_location || api.location || api.header}`" class="api-coverage-row" :class="{covered: api.covered}">
            <div class="api-state"><span class="api-state-icon" :class="{covered: api.covered}" :title="api.covered ? '已覆盖' : '未覆盖'"></span></div>
            <div class="api-name-cell">
              <strong>{{ api.name }}</strong>
              <span>{{ api.headerName }}</span>
            </div>
            <div class="api-driver-icons">
              <span v-for="driver in api.drivers" :key="`${api.name}:${driver.driver_id}:${driver.seq || 0}`" class="api-driver-icon" :title="ui.apiDriverTitle(driver)">{{ ui.apiDriverLabel(driver) }}</span>
              <span v-if="!api.drivers.length" class="api-driver-icon empty" title="未覆盖">-</span>
            </div>
          </div>
        </div>
        <div v-else class="api-coverage-list driver-api-coverage-list">
          <div class="driver-api-coverage-row head">
            <div>子 driver</div>
            <div>覆盖 API</div>
          </div>
          <div v-if="!ui.apiDriverCoverageVisibleRows.length" class="cov-empty">暂无 driver 覆盖导出 API</div>
          <div v-for="driver in ui.apiDriverCoverageVisibleRows" v-else :key="driver.key" class="driver-api-coverage-row">
            <div class="api-driver-cell">
              <span class="api-driver-icon" :title="ui.apiDriverTitle(driver)">{{ ui.apiDriverLabel(driver) }}</span>
              <div>
                <strong>{{ ui.apiDriverTitle(driver) }}</strong>
                <span>{{ driver.meta }}</span>
              </div>
            </div>
            <div class="driver-api-list">
              <span
                v-for="api in driver.apis"
                :key="`${driver.key}:${api.name}:${api.decl_location || api.location || api.header}`"
                class="driver-api-chip"
                :title="api.headerName"
              >
                <strong>{{ api.name }}</strong>
                <small>{{ api.headerName }}</small>
              </span>
            </div>
          </div>
        </div>
      </section>

      <section v-if="ui.coverageIsMulti" class="coverage-card">
        <div class="coverage-card-head"><h3>子 driver</h3><span>{{ ui.coverageDriverMeta }}</span></div>
        <div class="coverage-driver-tools">
          <div class="coverage-filter-pills" aria-label="driver 覆盖筛选">
            <button
              v-for="option in ui.coverageDriverFilters"
              :key="option.id"
              type="button"
              :class="{active: ui.coverageDriverFilter === option.id}"
              @click="ui.setCoverageDriverFilter(option.id)"
            >{{ option.label }}</button>
          </div>
          <label class="filter-control compact-select">
            <span>排序</span>
            <select :value="ui.coverageDriverSort" @change="ui.setCoverageDriverSort($event.target.value)">
              <option v-for="option in ui.coverageDriverSorts" :key="option.id" :value="option.id">{{ option.label }}</option>
            </select>
          </label>
        </div>
        <div class="driver-cov-list">
          <div v-if="!ui.coverageTargets.length" class="cov-empty">等待 multi-driver 调度数据</div>
          <div v-else-if="!ui.coverageDriverRows.length" class="cov-empty">当前筛选没有匹配的子 driver</div>
          <template v-else>
            <div class="driver-cov-row head">
              <div v-for="column in ui.driverColumns" :key="column.id" class="driver-th"><span>{{ column.label }}</span><span class="help" :title="column.help" tabindex="0">?</span></div>
            </div>
            <div v-for="target in ui.coverageDriverRows" :key="target.key" class="driver-cov-row" :class="target.className">
              <div class="driver">d{{ target.driverId || '-' }}</div>
              <div class="status">{{ target.status }}</div>
              <div>v{{ target.seq || 0 }}</div>
              <div>{{ target.seeds }}</div>
              <div>{{ target.executed }}</div>
              <div>{{ target.full }}</div>
              <div>{{ target.partial }}</div>
              <div>{{ target.uncovered }}</div>
              <div>{{ target.apiCount }}</div>
              <div>{{ target.crashCount }}</div>
              <div><button class="driver-detail-button" type="button" :disabled="!target.hasDetails" @click="ui.openDriverCoverage(target.driverId, target.seq)">查看</button></div>
            </div>
          </template>
        </div>
      </section>
    </div>
  </section>
</template>
