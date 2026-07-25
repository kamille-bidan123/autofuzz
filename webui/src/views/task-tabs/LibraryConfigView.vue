<script setup>
import { ArrowLeft, Save } from '@lucide/vue';
import { useAutofuzz } from '../../appContext';

const ui = useAutofuzz();
</script>

<template>
  <div class="subview library-config-view">
    <div class="subview-head">
      <button class="back-button icon-text-button" type="button" @click="ui.closeLibraryConfig">
        <ArrowLeft :size="15" />
        <span>返回</span>
      </button>
      <div>
        <h2>library.toml</h2>
        <p>
          <template v-if="ui.detail.libraryConfig.path">{{ ui.detail.libraryConfig.path }}</template>
          <template v-else>配置文件</template>
          <template v-if="ui.detail.libraryConfig.updatedAt"> · {{ ui.formatDate(ui.detail.libraryConfig.updatedAt) }}</template>
        </p>
      </div>
    </div>

    <section class="panel library-config-panel">
      <div v-if="ui.detail.libraryConfig.status === 'loading'" class="driver-detail-empty">正在加载 library.toml...</div>
      <div v-else-if="!ui.detail.libraryConfig.available" class="driver-detail-empty">
        {{ ui.detail.libraryConfig.message || 'library.toml 尚未生成' }}
      </div>
      <div v-else class="library-config-content">
        <div v-if="ui.detail.libraryConfig.message" class="inline-alert" role="status">
          {{ ui.detail.libraryConfig.message }}
        </div>
        <textarea
          v-model="ui.detail.libraryConfig.content"
          class="library-config-editor"
          spellcheck="false"
          :readonly="!ui.detail.libraryConfig.editable || ui.detailActionBusy.library"
        ></textarea>
        <div class="library-config-actions">
          <button
            class="primary icon-text-button"
            type="button"
            :disabled="!ui.canReprocessLibraryConfig"
            @click="ui.submitLibraryConfigReprocess"
          >
            <Save :size="15" />
            <span>{{ ui.detailActionBusy.library ? '处理中...' : '保存并重新处理' }}</span>
          </button>
          <button class="driver-detail-button" type="button" @click="ui.closeLibraryConfig">关闭</button>
        </div>
      </div>
    </section>
  </div>
</template>
