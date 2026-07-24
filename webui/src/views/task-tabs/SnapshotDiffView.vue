<script setup>
import { ArrowLeft } from '@lucide/vue';
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <section class="subview">
    <div class="subview-head">
      <button class="back-button icon-text-button" type="button" @click="ui.closeSnapshotDiff"><ArrowLeft :size="16" /><span>Snapshot</span></button>
      <div><h2>{{ ui.detail.snapshotDiff.title }}</h2><p>{{ ui.detail.snapshotDiff.meta }}</p></div>
    </div>
    <section class="panel">
      <div v-if="ui.detail.snapshotDiff.status !== 'ready'" class="diff-empty">{{ ui.detail.snapshotDiff.message }}</div>
      <pre v-else-if="ui.diffLines.length" class="diff-code"><span v-for="(line, index) in ui.diffLines" :key="index" class="diff-line" :class="line.className">{{ line.text }}</span></pre>
      <div v-else class="diff-empty">两个版本的 target driver 源码完全一致。</div>
    </section>
  </section>
</template>
