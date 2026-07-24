<script setup>
import { onMounted, onUnmounted, ref, watch } from 'vue';
import { useAutofuzz } from '../../appContext';

const ui = useAutofuzz();
const terminalElement = ref(null);
const status = ref('loading');
let terminal = null;
let fitAddon = null;
let renderedLines = 0;
let disposed = false;

function writeLine(line) {
  const rawMessage = String(line.message ?? '');
  const controlOnly = rawMessage.replace(/[\r\n]/g, '') === '';
  const source = !controlOnly && line.source ? `\x1b[36m${line.source}\x1b[0m ` : '';
  const message = rawMessage.replace(/\r\n/g, '\n').replace(/\n/g, '\r\n');
  const suffix = message.endsWith('\r') || message.endsWith('\n') ? '' : '\r\n';
  terminal?.write(`${source}${message}${suffix}`);
}

function renderPendingLines(forceReset = false) {
  if (!terminal) return;
  if (forceReset || ui.detail.logs.length < renderedLines) {
    terminal.reset();
    renderedLines = 0;
  }
  ui.detail.logs.slice(renderedLines).forEach(writeLine);
  renderedLines = ui.detail.logs.length;
}

function fitTerminal() {
  try {
    fitAddon?.fit();
  } catch (_) {
    // The container can be between layout states during route transitions.
  }
}

const stopWatching = watch(
  [() => ui.detail.id, () => ui.detail.logs.length],
  ([taskId], [previousTaskId]) => renderPendingLines(taskId !== previousTaskId)
);

onMounted(async () => {
  try {
    const [{Terminal}, {FitAddon}] = await Promise.all([
      import('@xterm/xterm'),
      import('@xterm/addon-fit'),
      import('@xterm/xterm/css/xterm.css')
    ]);
    if (disposed || !terminalElement.value) return;
    terminal = new Terminal({
      theme: {
        background: '#111827',
        foreground: '#dbe5f5',
        selectionBackground: '#475569'
      },
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, "Cascadia Code", monospace',
      fontSize: 11,
      lineHeight: 1.35,
      scrollback: 5000,
      convertEol: false,
      disableStdin: true,
      cursorBlink: false
    });
    fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(terminalElement.value);
    fitTerminal();
    renderPendingLines(true);
    status.value = 'ready';
    window.addEventListener('resize', fitTerminal);
  } catch (error) {
    status.value = error.message || '终端加载失败';
  }
});

onUnmounted(() => {
  disposed = true;
  stopWatching();
  window.removeEventListener('resize', fitTerminal);
  terminal?.dispose();
  terminal = null;
  fitAddon = null;
});
</script>

<template>
  <section class="panel stream">
    <div class="stream-title"><h3>运行日志</h3><span>{{ ui.detail.logs.length }} 行</span></div>
    <div class="terminal-shell">
      <div v-if="status !== 'ready'" class="terminal-status">{{ status === 'loading' ? '正在加载终端...' : status }}</div>
      <div ref="terminalElement" class="runtime-terminal" role="log" aria-label="Autofuzz 运行日志"></div>
    </div>
  </section>
</template>

<style>
.terminal-shell { position: relative; height: calc(100vh - 190px); min-height: 560px; background: #111827; }
.runtime-terminal { width: 100%; height: 100%; padding: 7px; }
.terminal-status { position: absolute; inset: 0; display: grid; place-items: center; color: #94a3b8; font-size: 12px; }
@media (max-width: 960px) {
  .terminal-shell { height: 70vh; min-height: 420px; }
}
</style>
