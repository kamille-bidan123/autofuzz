<script setup>
import { useAutofuzz } from '../../appContext';
const ui = useAutofuzz();
</script>

<template>
  <section class="panel stream">
    <div class="stream-title"><h3>Codex CLI 实时事件</h3><span>{{ ui.detail.codexEvents.length }} 条</span></div>
    <div :ref="element => { ui.codexEventsRef = element }" class="event-list">
      <div v-if="!ui.detail.codexEvents.length" class="empty">{{ ui.detail.codexEmpty }}</div>
      <template v-for="event in ui.detail.codexEvents" :key="event.id">
        <article v-if="event.kind === 'message'" class="codex-event message" :class="event.role">
          <div class="codex-message-meta">[{{ event.stage }}] {{ event.role === 'user' ? 'user' : 'assistant' }}</div>
          <div class="codex-message-bubble"><div class="codex-markdown" v-html="event.html"></div></div>
        </article>
        <details v-else-if="event.kind === 'thinking'" class="codex-event thinking"><summary>[{{ event.stage }}] thinking</summary><pre>{{ event.text || '(empty thinking)' }}</pre></details>
        <details v-else-if="event.kind === 'command'" class="codex-event command">
          <summary class="codex-exec-summary"><span class="codex-exec-prefix">[{{ event.stage }}] exec:</span><span class="codex-exec-cmd" :title="event.command">{{ event.preview }}</span><span v-if="event.status" class="codex-exec-status">{{ event.status }}</span></summary>
          <div class="codex-exec-body"><div class="codex-exec-label">完整命令</div><pre>{{ event.command }}</pre><template v-if="event.output"><div class="codex-exec-label">输出</div><pre>{{ event.output }}</pre></template></div>
        </details>
        <details v-else class="codex-event raw"><summary>[{{ event.stage }}] {{ event.label }}</summary><pre>{{ event.raw }}</pre></details>
      </template>
    </div>
  </section>
</template>
