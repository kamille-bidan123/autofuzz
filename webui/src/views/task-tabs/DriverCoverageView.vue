<script setup>
import { ref } from 'vue';
import { ArrowLeft } from '@lucide/vue';
import { useAutofuzz } from '../../appContext';

const ui = useAutofuzz();
const mode = ref('graph');
</script>

<template>
  <section class="subview driver-coverage-page">
    <div class="subview-head">
      <button class="back-button icon-text-button" type="button" @click="ui.closeDriverCoverage">
        <ArrowLeft :size="16" />
        <span>Coverage</span>
      </button>
      <div>
        <h2>{{ ui.driverCoverageTitle }}</h2>
        <div class="driver-detail-meta"><span v-for="item in ui.driverCoverageMeta" :key="item">{{ item }}</span></div>
      </div>
    </div>

    <section class="panel driver-coverage-content">
      <div class="segmented-control" role="tablist" aria-label="覆盖详情模式">
        <button type="button" role="tab" :aria-selected="mode === 'graph'" :class="{active: mode === 'graph'}" @click="mode = 'graph'">覆盖 Graph</button>
        <button type="button" role="tab" :aria-selected="mode === 'list'" :class="{active: mode === 'list'}" @click="mode = 'list'">函数列表</button>
      </div>

      <div v-if="!ui.detail.coverageDetail.driverId" class="driver-detail-empty">请选择子 driver。</div>
      <div v-else-if="!ui.coverageData" class="driver-detail-empty">正在加载子 driver 覆盖详情...</div>
      <div v-else-if="!ui.driverCoverageMeta.length" class="driver-detail-empty">当前覆盖快照里没有这个子 driver。</div>
      <section v-else-if="mode === 'graph'" class="driver-graph">
        <div class="driver-graph-head"><h3>函数级覆盖 Graph</h3><span>{{ ui.driverGraphNote }}</span></div>
        <div v-if="ui.detail.coverageDetail.sourceStatus === 'error'" class="driver-graph-empty error-text">{{ ui.detail.coverageDetail.sourceMessage }}</div>
        <div v-else-if="!ui.driverGraphGroups.length" class="driver-graph-empty">正在加载可渲染的函数覆盖节点...</div>
        <div v-else class="driver-graph-files">
          <div v-for="group in ui.driverGraphGroups" :key="group.file" class="driver-graph-file">
            <div class="driver-graph-file-title">{{ group.file || '(unknown file)' }} · {{ group.nodes.length }} 个函数块</div>
            <div class="driver-graph-chain">
              <article v-for="node in group.nodes" :key="`${node.file}:${node.function}:${node.start_line}`" class="driver-graph-node" :class="node.coverage || 'full'">
                <div class="driver-graph-node-head"><div class="driver-graph-node-name">{{ node.function || '(anonymous)' }}</div><div class="driver-graph-node-meta">{{ node.meta }}</div></div>
                <pre v-if="node.sourceLines.length" class="driver-graph-code"><span v-for="(line, index) in node.sourceLines" :key="index" class="driver-code-line" :class="line.className" :title="line.title"><span class="driver-line-no">{{ line.no }}</span><span>{{ line.text }}</span></span></pre>
                <pre v-else class="driver-graph-code empty">{{ node.emptyText }}</pre>
                <div v-if="(node.uncovered_branches || []).length" class="driver-graph-branches">
                  <div v-for="(branch, index) in (node.uncovered_branches || []).slice(0, 6)" :key="index" class="driver-graph-branch">{{ ui.branchLocation(branch) }} · {{ branch.condition || '(unknown condition)' }}<template v-if="branch.missing"> · 缺失: {{ branch.missing }}</template></div>
                </div>
              </article>
            </div>
          </div>
        </div>
      </section>

      <div v-else class="driver-detail-grid">
        <section v-for="section in ui.driverFunctionSections" :key="section.kind" class="driver-detail-section">
          <h3><span>{{ section.title }}</span><span>{{ section.functions.length }} 个</span></h3>
          <div class="driver-function-list">
            <div v-if="!section.functions.length" class="driver-detail-empty">暂无{{ section.title }}</div>
            <div v-for="fn in section.functions" v-else :key="`${fn.file}:${fn.function}:${fn.start_line}`" class="driver-function">
              <div class="driver-function-name">{{ fn.function || '(anonymous)' }}</div>
              <div class="driver-function-meta">{{ fn.file || '(unknown file)' }} · 调用 {{ fn.entry_count || 0 }} 次</div>
              <div v-if="section.kind === 'partial' && (fn.uncovered_branches || []).length" class="driver-branch-list">
                <div v-for="(branch, index) in (fn.uncovered_branches || []).slice(0, 20)" :key="index" class="driver-branch">{{ ui.branchLocation(branch) }} · {{ branch.condition || '(unknown condition)' }}</div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </section>
  </section>
</template>
