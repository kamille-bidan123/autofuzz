<script setup>
import { ArrowLeft } from '@lucide/vue';
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <section class="subview">
    <div class="subview-head">
      <button class="back-button icon-text-button" type="button" @click="ui.closeCrashReport"><ArrowLeft :size="16" /><span>Crash</span></button>
      <div><h2>{{ ui.detail.crashReport.title }}</h2><p>{{ ui.detail.crashReport.meta }}</p></div>
    </div>
    <section class="panel">
      <div v-if="ui.detail.crashReport.status !== 'ready'" class="diff-empty">{{ ui.detail.crashReport.message }}</div>
      <div v-else-if="!ui.crashReportCards.length" class="diff-empty">
        {{ ui.detail.crashReport.focusFile ? '未找到该 crash 的分析报告。' : '当前 snapshot 还没有 unique crash 分析报告。' }}
      </div>
      <div v-else class="crash-report-list">
        <article v-for="card in ui.crashReportCards" :key="card.file" class="crash-report-card" :class="{focused: card.focused}">
          <div class="crash-report-head">
            <div><h3>{{ card.file }}</h3><p>{{ card.meta }}<template v-if="card.affected"> · {{ card.affected }}</template></p></div>
            <div class="crash-report-actions">
              <span class="crash-class" :class="card.badge.className">{{ card.badge.label }}</span>
              <button type="button" class="driver-detail-button crash-analyze-button" :disabled="!card.canAnalyze" @click="ui.analyzeCrashReport(card)">{{ card.analyzeLabel }}</button>
            </div>
          </div>
          <div class="crash-report-body">
            <section v-for="section in card.sections" :key="section.title" class="crash-report-section">
              <h4>{{ section.title }}</h4>
              <ul v-if="section.items"><li v-for="(item, index) in section.items" :key="index">{{ item }}</li></ul>
              <div v-else-if="section.html" class="codex-markdown crash-analysis-markdown" v-html="section.html"></div>
              <p v-else>{{ section.text }}</p>
            </section>
          </div>
        </article>
      </div>
    </section>
  </section>
</template>
