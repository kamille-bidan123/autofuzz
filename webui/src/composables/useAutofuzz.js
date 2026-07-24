import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

const statusLabels = {
  pending: '待启动',
  running: '运行中',
  stopping: '停止中',
  stopped: '已停止',
  interrupted: '已中断',
  completed: '已完成',
  failed: '运行失败',
  missing: '数据缺失'
};

const mainViewTitles = {
  dashboard: ['Dashboard', '任务状态、发现问题与 crash 分析队列概览'],
  tasks: ['Tasks', '创建、启动并查看所有 Autofuzz 任务'],
  detail: ['Task Detail', '查看阶段、覆盖、crash、snapshot 与日志']
};

const statusColumns = [
  { label: '运行中', statuses: ['running', 'stopping'] },
  { label: '待启动', statuses: ['pending'] },
  { label: '已完成', statuses: ['completed'] },
  { label: '需关注', statuses: ['failed', 'interrupted', 'missing', 'stopped'] }
];

const stageDefs = [
  { id: 'cloned', name: '准备源码', owner: 'Go', index: 1 },
  { id: 'built', name: '自主构建', owner: 'Codex CLI', index: 2 },
  { id: 'configured', name: '生成 library.toml', owner: 'Codex CLI', index: 3 },
  { id: 'preprocessed', name: 'API 预处理', owner: 'PromeFuzz', index: 4 },
  { id: 'comprehended', name: 'API 理解', owner: 'PromeFuzz + Codex', index: 5 },
  { id: 'generated', name: 'All-cover 全量生成', owner: 'PromeFuzz + Codex', index: 6 },
  { id: 'fuzzing', name: '持续 Fuzz 测试', owner: 'libFuzzer', index: 7 }
];

const crashFixChildStageDefs = [
  { id: 'built', name: '修复并编译库', owner: 'Codex CLI', index: 1 },
  { id: 'generated', name: '编译 fuzz_driver', owner: 'Go', index: 2 },
  { id: 'fuzzing', name: '持续 Fuzz 测试', owner: 'libFuzzer', index: 3 }
];

const detailTabs = [
  { id: 'overview', label: 'Overview' },
  { id: 'coverage', label: 'Coverage' },
  { id: 'crashes', label: 'Crashes' },
  { id: 'snapshots', label: 'Snapshots' },
  { id: 'codex', label: 'Codex Events' },
  { id: 'logs', label: 'Logs' }
];

const flowPhaseLabels = {
  starting: '正在准备初始 fuzz driver',
  fuzzing: '等待下一轮分析',
  collecting: '正在收集覆盖与运行状态',
  selecting_target: '正在选择平台期 driver',
  prechecking: '正在预检临时 driver',
  analyzing: 'Codex 正在分析优化机会',
  applying: '正在校验分析结果与源码变化',
  validating: '正在复核 proof seed',
  promoting: '正在转正新快照',
  rebuilding: '正在重建并重启 driver',
  restarting: '正在重启 driver'
};

const activeFlowPhases = [
  'collecting',
  'selecting_target',
  'prechecking',
  'analyzing',
  'applying',
  'validating',
  'promoting',
  'rebuilding',
  'restarting'
];

function countTaskStatuses(tasks) {
  const counts = {
    total: tasks.length,
    pending: 0,
    running: 0,
    stopping: 0,
    stopped: 0,
    interrupted: 0,
    completed: 0,
    failed: 0,
    missing: 0,
    other: 0
  };
  for (const task of tasks) {
    if (Object.prototype.hasOwnProperty.call(counts, task.status)) counts[task.status]++;
    else counts.other++;
  }
  return counts;
}

function overviewFromRuns(tasks) {
  return {
    tasks: countTaskStatuses(tasks),
    issues: {
      discovered_total: 0,
      unique_crashes_total: 0,
      library_bugs: 0,
      fuzz_driver_bugs: 0,
      pending_analysis: 0
    },
    crash_queue: { total: 0, queued: 0, running: 0 },
    recent_tasks: tasks.slice(0, 8),
    recent_issues: []
  };
}

function safeClass(value) {
  return String(value || '').replace(/[^a-z0-9_-]/gi, '');
}

function crashReportBadge(status, classification) {
  if (status === 'skipped') return { className: 'skipped', label: '已跳过' };
  if (status === 'queued') return { className: 'queued', label: '排队中' };
  if (status === 'pending') return { className: 'pending', label: '未分析' };
  if (status === 'running') return { className: 'running', label: '分析中' };
  if (status === 'failed') return { className: 'failed', label: '分析失败' };
  if (classification === 'library_bug') return { className: 'library_bug', label: '库问题' };
  if (classification === 'fuzz_driver_bug') return { className: 'fuzz_driver_bug', label: 'driver 问题' };
  if (classification === 'unknown') return { className: 'unknown', label: '根因未知' };
  return { className: 'pending', label: '未分类' };
}

function crashReportStatusLabel(value) {
  if (value === 'completed') return '已完成';
  if (value === 'queued') return '排队中';
  if (value === 'running') return '分析中';
  if (value === 'failed') return '失败';
  if (value === 'pending') return '等待分析';
  if (value === 'skipped') return '已跳过';
  return value || '未知';
}

const uniqueCrashFilterColumns = ['crash', 'status', 'type'];

function filterText(value, fallback = '未标注') {
  const text = String(value || '').trim();
  return text || fallback;
}

function crashEntryForFilter(item) {
  return item?.entry || {};
}

export function crashFilenameKind(file) {
  const base = String(file || '').split(/[\\/]/).pop().trim().toLowerCase();
  if (!base) return 'unknown';
  for (const marker of ['slow-unit', 'slowunit', 'timeout', 'leak', 'oom', 'crash']) {
    if (base === marker || base.startsWith(`${marker}-`)) return marker === 'slowunit' ? 'slow-unit' : marker;
  }
  const match = base.match(/^([a-z0-9_]+)-/);
  return match?.[1] || 'unknown';
}

function uniqueCrashStatusFilterValue(item) {
  const entry = crashEntryForFilter(item);
  const badge = crashReportBadge(entry.report_status || 'pending', entry.classification || '');
  return `${badge.className}:${badge.label}`;
}

function uniqueCrashFilterValue(column, item) {
  const entry = crashEntryForFilter(item);
  if (column === 'crash') return crashFilenameKind(entry.file);
  if (column === 'status') return uniqueCrashStatusFilterValue(item);
  if (column === 'type') return filterText(entry.type);
  return '';
}

function uniqueCrashFilterOptionLabel(column, value) {
  if (column === 'status') return String(value || '').split(':').slice(1).join(':') || '未知';
  return value || 'unknown';
}

function uniqueCrashFilterSortWeight(column, value) {
  if (column === 'crash') {
    const order = ['crash', 'leak', 'timeout', 'slow-unit', 'oom', 'unknown'];
    const index = order.indexOf(value);
    return index >= 0 ? index : 100;
  }
  if (column === 'status') {
    const order = ['library_bug', 'fuzz_driver_bug', 'unknown', 'pending', 'queued', 'running', 'failed', 'skipped'];
    const index = order.findIndex(marker => String(value || '').startsWith(`${marker}:`));
    return index >= 0 ? index : 100;
  }
  return 0;
}

export function buildUniqueCrashFilterOptions(items, column) {
  const counts = new Map();
  for (const item of Array.isArray(items) ? items : []) {
    const value = uniqueCrashFilterValue(column, item);
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({value, label: uniqueCrashFilterOptionLabel(column, value), count}))
    .sort((a, b) => {
      const weight = uniqueCrashFilterSortWeight(column, a.value) - uniqueCrashFilterSortWeight(column, b.value);
      if (weight !== 0) return weight;
      return a.label.localeCompare(b.label);
    });
}

function normalizedSelection(selection) {
  if (!selection) return null;
  if (selection instanceof Set) return selection;
  if (Array.isArray(selection)) return new Set(selection);
  return null;
}

export function filterUniqueCrashItems(items, selections = {}) {
  return (Array.isArray(items) ? items : []).filter(item => uniqueCrashFilterColumns.every(column => {
    const selected = normalizedSelection(selections[column]);
    return !selected || selected.has(uniqueCrashFilterValue(column, item));
  }));
}

function formatLocalDateTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

const CODEX_CMD_PREVIEW_LIMIT = 140;

function codexString(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); }
}

function truncateText(text, max) {
  const s = String(text || '');
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}...`;
}

function codexItemText(item) {
  return codexString(item.text ?? item.message ?? item.content ?? item.delta ?? '');
}

function codexCommandText(item) {
  return codexString(item.command ?? item.cmd ?? item.argv ?? '');
}

function isCodexMessageItem(item) {
  const type = String(item.type || '');
  return type === 'agent_message' || type === 'assistant_message' || type === 'user_message' ||
    (type.includes('message') && Boolean(codexItemText(item)));
}

function escapeHtmlText(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function markdownToHtml(text) {
  return String(text ?? '')
    .split(/\r?\n/)
    .map(line => escapeHtmlText(line))
    .join('<br>') || '(empty message)';
}

function reportSection(title, text) {
  const value = codexString(text);
  if (!value) return null;
  return {title, text: value};
}

function crashReportAnalyzeLabel(status) {
  if (status === 'queued') return '排队中';
  if (status === 'running') return '分析中';
  if (status === 'skipped') return '不可分析';
  return status === 'completed' ? '重新分析' : '分析';
}

function isOOBCrashType(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) return false;
  return [
    'heap-buffer-overflow',
    'stack-buffer-overflow',
    'global-buffer-overflow',
    'dynamic-stack-buffer-overflow',
    'container-overflow',
    'out-of-bounds',
    'index-out-of-bounds',
    'oob'
  ].some(marker => normalized.includes(marker));
}

function buildCrashReportCard(item, focusFile) {
  const entry = item?.entry || {};
  const envelope = item?.report || {};
  const report = envelope.report || envelope || {};
  const status = entry.report_status || 'pending';
  const classification = entry.classification || report.classification || '';
  const file = entry.file || report.crash_file || '(unknown crash)';
  const meta = [
    `状态: ${crashReportStatusLabel(status)}`,
    entry.type ? `类型: ${entry.type}` : ''
  ].filter(Boolean).join(' · ');
  const asanReport = report.asan_report || entry.asan_report || envelope.asan_report || envelope.stack_signature || '';
  const sections = [
    reportSection('ASan 报告', asanReport),
    reportSection('分析结论', report.analysis || entry.report_error || item?.error || '等待 LLM 分析输出'),
    reportSection('错误', entry.report_error || item?.error)
  ].filter(Boolean);
  if (!sections.length) sections.push({title: '状态', text: '暂无报告正文'});
  return {
    file,
    meta,
    affected: '',
    sections,
    status,
    badge: crashReportBadge(status, classification),
    canAnalyze: status !== 'queued' && status !== 'running' && status !== 'skipped',
    analyzeLabel: crashReportAnalyzeLabel(status),
    focused: Boolean(focusFile && file === focusFile)
  };
}

export function buildCrashReportCards(items, focusFile = '') {
  const cards = (Array.isArray(items) ? items : []).map(item => buildCrashReportCard(item, focusFile));
  if (!focusFile) return cards;
  return cards.filter(card => card.file === focusFile);
}

const driverColumns = [
  { id: 'driver', label: 'driver', help: '子 driver 编号，对应 driver-targets/driver-XXXX' },
  { id: 'status', label: '运行状态', help: '当前调度状态：运行中、排队、构建失败、启动失败等' },
  { id: 'seq', label: '版本', help: '该子 driver 当前快照版本，例如 v1、v2' },
  { id: 'seed', label: 'corpus seed', help: '当前子 driver corpus 目录中的输入数量' },
  { id: 'executed', label: '已执行函数', help: '该子 driver 当前覆盖中至少执行过一次的函数数量' },
  { id: 'full', label: '完全覆盖函数', help: '已执行且没有剩余未覆盖分支的函数数量' },
  { id: 'partial', label: '部分覆盖函数', help: '已执行但仍存在未覆盖分支的函数数量' },
  { id: 'uncovered', label: '未覆盖分支数量', help: '部分覆盖函数中仍未走到的具体分支数量，不是未执行函数数量' },
  { id: 'detail', label: '详情', help: '查看该子 driver 完全覆盖和部分覆盖的函数明细' }
];

function targetStatusLabel(status) {
  const labels = {
    running: '运行中',
    queued: '排队',
    ready: '就绪',
    build_failed: '构建失败',
    start_failed: '启动失败',
    historical: '历史',
    stopped: '已停止'
  };
  return labels[status] || status || '-';
}

function driverRowClass(target) {
  const status = target?.status || '';
  if (status.includes('failed')) return 'failed';
  if (target?.plateau) return 'plateau';
  if (status === 'running') return 'running';
  if (status === 'queued' || status === 'ready') return 'queued';
  return '';
}

function hasDriverCoverageDetails(target) {
  const cov = target?.coverage || {};
  return (cov.full || []).length > 0 || (cov.partial || []).length > 0;
}

function isDriverCoverageRouteName(name) {
  return name === 'driver-coverage' || name === 'driver-coverage-latest';
}

function driverVersionKey(driverId, seq) {
  return `${Number(driverId || 0)}:${Number(seq || 0)}`;
}

function schedulerEntryKey(value) {
  if (value && typeof value === 'object') {
    const driverId = Number(value.driver_id || 0);
    const seq = Number(value.seq || 0);
    if (driverId <= 0) return '';
    return seq > 0 ? driverVersionKey(driverId, seq) : `${driverId}:*`;
  }
  const driverId = Number(value || 0);
  return driverId > 0 ? `${driverId}:*` : '';
}

function schedulerEntrySet(values) {
  return new Set((values || []).map(schedulerEntryKey).filter(Boolean));
}

function schedulerHasEntry(set, driverId, seq) {
  const id = Number(driverId || 0);
  if (id <= 0) return false;
  return set.has(driverVersionKey(id, seq)) || set.has(`${id}:*`);
}

function coverageTargetRef(target) {
  return {driver_id: Number(target?.driver_id || 0), seq: Number(target?.seq || 0)};
}

function schedulerLists(data) {
  const targets = data?.targets || [];
  const statusRefs = statuses => targets
    .filter(target => statuses.includes(target.status))
    .map(coverageTargetRef)
    .filter(ref => ref.driver_id > 0);
  return {
    targets,
    running: Array.isArray(data?.running_versions)
      ? data.running_versions
      : Array.isArray(data?.running_targets) ? data.running_targets : statusRefs(['running']),
    queued: Array.isArray(data?.queued_versions)
      ? data.queued_versions
      : Array.isArray(data?.queued_targets) ? data.queued_targets : statusRefs(['queued', 'ready']),
    next: Array.isArray(data?.next_versions)
      ? data.next_versions
      : Array.isArray(data?.next_targets) ? data.next_targets : []
  };
}

function formatCountdown(seconds) {
  const total = Math.max(0, Math.ceil(Number(seconds) || 0));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const two = value => String(value).padStart(2, '0');
  if (hours > 0) return `${hours}:${two(minutes)}:${two(secs)}`;
  return `${two(minutes)}:${two(secs)}`;
}

export function buildDriverSchedule(data, targets = [], currentTime = Date.now(), receivedAt = currentTime) {
  if (data?.mode !== 'multi') return null;
  const {running, queued, next} = schedulerLists(data);
  const runningEntries = schedulerEntrySet(running);
  const nextEntries = schedulerEntrySet(next);
  const items = [...(targets || [])]
    .filter(target => Number(target?.driver_id || 0) > 0)
    .sort((a, b) => {
      const driverDelta = Number(a.driver_id || 0) - Number(b.driver_id || 0);
      if (driverDelta !== 0) return driverDelta;
      return Number(a.seq || 0) - Number(b.seq || 0);
    })
    .map(target => {
      const driverId = Number(target.driver_id || 0);
      const seq = Number(target.seq || 0);
      const state = target.status === 'running' || schedulerHasEntry(runningEntries, driverId, seq)
        ? 'running'
        : schedulerHasEntry(nextEntries, driverId, seq) ? 'next' : 'idle';
      const stateLabel = state === 'running' ? '正在运行' : state === 'next' ? '下一批次' : '等待';
      return {
        key: driverVersionKey(driverId, seq),
        driverId,
        seq,
        state,
        ariaLabel: `子 driver d${driverId}，版本 v${seq}，${stateLabel}`
      };
    });
  const runningCount = items.filter(item => item.state === 'running').length;
  const reportedRemaining = Number(data.analysis_remaining_seconds || 0);
  const deadline = data.next_analysis_at ? Date.parse(data.next_analysis_at) : 0;
  const snapshotTime = data.timestamp ? Date.parse(data.timestamp) : 0;
  const hasDeadline = Number.isFinite(deadline) && deadline > 0;
  const deadlineRemaining = hasDeadline
    ? Math.max(0, Math.ceil((deadline - (Number.isFinite(snapshotTime) && snapshotTime > 0 ? snapshotTime : currentTime)) / 1000))
    : 0;
  const initialRemaining = reportedRemaining > 0 ? reportedRemaining : deadlineRemaining;
  const elapsed = receivedAt > 0 ? Math.max(0, Math.floor((currentTime - receivedAt) / 1000)) : 0;
  const remaining = Math.max(0, initialRemaining - elapsed);
  const hasCountdown = initialRemaining > 0 || hasDeadline;
  return {
    meta: `轮次 ${data.iteration || 0} · 运行 ${runningCount}/${items.length} · 等待 ${(queued || []).length} · 并发 ${data.max_parallel_targets || '-'}`,
    countdown: hasCountdown ? (remaining > 0 ? `下一轮 ${formatCountdown(remaining)}` : '下一轮 即将调度') : '',
    items
  };
}

function compareCoverageFunctions(a, b) {
  const af = a?.file || '';
  const bf = b?.file || '';
  if (af !== bf) return af.localeCompare(bf);
  const al = Number(a?.start_line || 0);
  const bl = Number(b?.start_line || 0);
  if (al !== bl) return al - bl;
  return String(a?.function || '').localeCompare(String(b?.function || ''));
}

function sortedCoverageFunctions(functions) {
  return [...(functions || [])].sort(compareCoverageFunctions);
}

function apiCoveragePercent(report) {
  const value = Number(report?.coverage || 0);
  return `${Math.round(value * 100)}%`;
}

function apiDriverLabel(driver) {
  const id = Number(driver?.driver_id || 0);
  return id > 0 ? `d${id}` : 'd-';
}

function apiDriverTitle(driver) {
  const label = apiDriverLabel(driver);
  const seq = Number(driver?.seq || 0);
  const version = seq > 0 ? ` / v${seq}` : '';
  return `${label}${version}`;
}

function apiHeaderName(path = '') {
  const text = String(path || '');
  return text.split('/').pop() || text || '-';
}

function compareAPICoverageRows(a, b) {
  if (a.covered !== b.covered) return a.covered ? -1 : 1;
  const nameDelta = String(a.name || '').localeCompare(String(b.name || ''));
  if (nameDelta !== 0) return nameDelta;
  return String(a.header || '').localeCompare(String(b.header || ''));
}

function branchLocation(branch) {
  const loc = branch?.location || [];
  if (branch?.expansion_line) {
    const macro = branch.file ? ` · 宏定义 ${shortPath(branch.file)}:L${loc[0] || '?'}:${loc[1] || 0}` : '';
    return `L${branch.expansion_line}:${branch.expansion_column || 0}${macro}`;
  }
  if (!loc.length) return 'L?';
  return `L${loc[0] || '?'}:${loc[1] || 0}`;
}

function shortPath(path) {
  const parts = String(path || '').split('/').filter(Boolean);
  if (parts.length <= 2) return path || '';
  return parts.slice(-2).join('/');
}

function coverageBranchLine(branch) {
  return `L${branch?.location ? branch.location[0] : '?'}`;
}

function branchCountsText(branch) {
  if (!branch?.counts) return '';
  try { return JSON.stringify(branch.counts); } catch (_) { return String(branch.counts); }
}

function coverageLabel(value) {
  return value === 'partial' ? '部分覆盖' : '完全覆盖';
}

function branchDisplayLine(branch) {
  return Number(branch?.expansion_line || (branch?.location || [])[0] || 0);
}

function lineCoverageClass(cov, hasUncoveredBranch, fallbackClass) {
  if (hasUncoveredBranch) return 'uncovered';
  if (!cov) return fallbackClass;
  if (cov.status === 'covered') return 'full';
  if (cov.status === 'uncovered') return 'uncovered';
  return fallbackClass;
}

function functionKey(fn) {
  return `${fn?.file || ''}\u0000${fn?.function || ''}\u0000${fn?.start_line || 0}`;
}

function functionSourceMap(sourceData) {
  const map = new Map();
  (sourceData?.functions || []).forEach(fn => map.set(functionKey(fn), fn));
  return map;
}

function sourceLinesForFunction(fn, source) {
  if (!source?.source) return [];
  const startLine = Number(source.start_line || fn.start_line || 1);
  const lineCoverage = new Map((source.lines || []).map(line => [Number(line.line || 0), line]));
  const uncoveredBranchLines = new Set((fn.uncovered_branches || []).map(branchDisplayLine).filter(Boolean));
  const baseClass = fn.coverage === 'partial' ? 'partial' : 'full';
  const lines = String(source.source || '').split('\n').map((text, idx) => {
    const lineNo = startLine + idx;
    const cov = lineCoverage.get(lineNo);
    return {
      no: lineNo,
      text: text || ' ',
      className: lineCoverageClass(cov, uncoveredBranchLines.has(lineNo), baseClass),
      title: cov ? `region count: ${cov.count || 0} · ${cov.status || 'unknown'}` : ''
    };
  });
  if (source.truncated) {
    lines.push({no: '...', text: '/* ... 源码块已截断 ... */', className: 'truncated', title: ''});
  }
  return lines;
}

function graphGroupsForTarget(target, sourceData, loading) {
  const cov = target?.coverage || {};
  const nodes = [
    ...(cov.full || []).map(fn => ({...fn, coverage: 'full'})),
    ...(cov.partial || []).map(fn => ({...fn, coverage: 'partial'}))
  ].sort(compareCoverageFunctions);
  const sourceMap = functionSourceMap(sourceData);
  const byFile = new Map();
  const groups = [];
  for (const fn of nodes) {
    const file = fn.file || '';
    if (!byFile.has(file)) {
      const group = {file, nodes: []};
      byFile.set(file, group);
      groups.push(group);
    }
    const source = sourceMap.get(functionKey(fn));
    const branchCount = (fn.uncovered_branches || []).length;
    byFile.get(file).nodes.push({
      ...fn,
      meta: `${coverageLabel(fn.coverage)} · L${fn.start_line || '?'}-${fn.end_line || '?'} · 调用 ${fn.entry_count || 0} 次${branchCount ? ' · 未覆盖分支 ' + branchCount : ''}`,
      source,
      sourceLines: sourceLinesForFunction(fn, source),
      emptyText: loading ? '正在加载源码片段…' : source?.error || '暂无源码片段；仅展示函数覆盖节点。'
    });
  }
  for (const group of groups) group.nodes.sort(compareCoverageFunctions);
  return groups;
}

export function useAutofuzzController() {
    const route = useRoute();
    const router = useRouter();
    const activeMainView = ref('dashboard');
    const selectedTaskId = ref('');
    const tasks = ref([]);
    const overview = ref(null);
    const overviewFallback = ref(true);
    const createModalOpen = ref(false);
    const codexEventsRef = ref(null);
    const nowMs = ref(Date.now());
    const coverageReceivedAtMs = ref(0);
    const taskBusy = reactive(new Set());
    let countdownTimer = 0;
    let taskPollTimer = 0;
    let overviewPollTimer = 0;
    const tasksLoading = ref(false);
    const overviewLoading = ref(false);
    let detailPollingVersion = 0;
    let detailSelectionVersion = 0;
    let diffRequestVersion = 0;
    let crashReportRequestVersion = 0;
    let eventSource = null;
    let pendingDetailFocus = null;
    const detailPollTimers = new Map();
    const detailResourceRequests = new Map();
    let coverageSourceRequest = 0;
    const driverSourceCache = new Map();
    const messages = reactive({ dashboard: '', list: '' });
    const detailActionBusy = reactive({resume: false, cancel: false, trigger: false});
    const crashQueueBusy = reactive(new Set());
    const crashFixMode = ref(false);
    const crashFixBusy = ref(false);
    const crashDeleteMode = ref(false);
    const crashDeleteBusy = ref(false);
    const crashFixMessage = ref('');
    const selectedCrashFixKeys = ref(new Set());
    const selectedCrashDeleteKeys = ref(new Set());
    const uniqueCrashFilters = reactive({
      open: '',
      selections: {
        crash: null,
        status: null,
        type: null
      }
    });
    const createForm = reactive({
      values: {
        repository_url: '',
        ref: '',
        workspace: '',
        promefuzz: '',
        promefuzz_config: '',
        python: '',
        jobs: 1,
        pool_size: 1,
        max_fuzz_drivers: 1,
        stop_after: 'fuzzing',
        codex_command: 'codex',
        codex_model: '',
        codex_profile: '',
        resume: false,
        verbose: false
      },
      message: 'Web 服务默认仅监听本机。对于不可信仓库，请在一次性容器或隔离虚拟机中运行。',
      submitting: false,
      pathPickers: {}
    });
    const pathPickerCache = new Map();
    const pathPickerDebounce = new Map();
    const detail = reactive({
      id: '',
      name: 'Task 详情',
      repo: '',
      taskKind: '',
      parentTaskId: '',
      originDriverId: 0,
      originDriverSeq: 0,
      originCrashes: [],
      status: '',
      statusText: '未启动',
      message: '',
      meta: '尚未选择任务',
      activeTab: 'overview',
      stages: [],
      fuzzStageStatus: 'pending',
      fuzzFlow: null,
      fuzzFlowHistory: [],
      crashQueue: [],
      uniqueCrashes: [],
      snapshots: [],
      snapshotDiff: {
        visible: false,
        title: 'Driver Diff',
        meta: '',
        status: 'idle',
        message: '正在加载 Driver 差异…',
        diff: ''
      },
      crashReport: {
        visible: false,
        title: 'Unique Crash 分析报告',
        meta: '',
        status: 'idle',
        message: '正在加载 crash 报告…',
        reports: [],
        focusFile: '',
        seq: 0,
        driverId: 0
      },
      coverage: {
        data: null
      },
      coverageDetail: {
        visible: false,
        driverId: 0,
        seq: 0,
        sourceData: null,
        sourceStatus: 'idle',
        sourceMessage: ''
      },
      codexEvents: [],
      codexEmpty: 'built / configured / fuzzing 阶段的 Codex JSONL 事件将在这里出现',
      logs: []
    });

    const taskCounts = computed(() => countTaskStatuses(tasks.value));
    const dashboardOverview = computed(() => {
      const data = overview.value || overviewFromRuns(tasks.value);
      return {
        ...data,
        tasks: taskCounts.value,
        recent_tasks: tasks.value.length ? tasks.value.slice(0, 8) : (data.recent_tasks || [])
      };
    });
    const runningTasks = computed(() => (taskCounts.value.running || 0) + (taskCounts.value.stopping || 0));
    const abnormalTasks = computed(() =>
      (taskCounts.value.failed || 0) + (taskCounts.value.interrupted || 0) + (taskCounts.value.missing || 0)
    );
    const discoveredIssues = computed(() => {
      const issues = dashboardOverview.value.issues || {};
      return issues.discovered_total || issues.unique_crashes_total || 0;
    });
    const queueTotal = computed(() => (dashboardOverview.value.crash_queue || {}).total || 0);
    const totalTaskNote = computed(() => overviewFallback.value ? '来自 /api/runs 降级统计' : 'registry 中的任务');
    const issueNote = computed(() => {
      const issues = dashboardOverview.value.issues || {};
      return `库问题 ${issues.library_bugs || 0} · driver 问题 ${issues.fuzz_driver_bugs || 0}`;
    });
    const queueNote = computed(() => {
      const queue = dashboardOverview.value.crash_queue || {};
      return `运行 ${queue.running || 0} · 排队 ${queue.queued || 0}`;
    });
    const recentTasks = computed(() => dashboardOverview.value.recent_tasks || []);
    const recentIssues = computed(() => dashboardOverview.value.recent_issues || []);
    const topbarTitle = computed(() => activeMainView.value === 'detail' ? detail.name : (mainViewTitles[activeMainView.value] || mainViewTitles.dashboard)[0]);
    const topbarSubtitle = computed(() => activeMainView.value === 'detail' ? (detail.id ? `Task ${detail.id}` : mainViewTitles.detail[1]) : (mainViewTitles[activeMainView.value] || mainViewTitles.dashboard)[1]);
    const runningSidebarLabel = computed(() => `${runningTasks.value} running`);
    const hasTaskDetail = computed(() => Boolean(selectedTaskId.value));
    const statusColumnsView = computed(() =>
      statusColumns.map(column => ({
        ...column,
        tasks: tasks.value.filter(task => column.statuses.includes(task.status))
      }))
    );
    const stageStatusMap = computed(() => {
      const map = {};
      for (const stage of detail.stages || []) map[stage.id] = stage.status || 'pending';
      return map;
    });
    const activeStageDefs = computed(() => detail.taskKind === 'crash_fix_child' ? crashFixChildStageDefs : stageDefs);
    const linearStages = computed(() =>
      activeStageDefs.value.filter(stage => stage.id !== 'fuzzing').map(stage => ({
        ...stage,
        status: stageStatusMap.value[stage.id] || 'pending',
        detail: '',
        result: ''
      }))
    );
    const flowActive = computed(() => detail.status === 'running' && detail.fuzzFlow && activeFlowPhases.includes(detail.fuzzFlow.phase));
    const flowForwardActive = computed(() => Boolean(flowActive.value && detail.fuzzFlow?.phase !== 'rebuilding'));
    const flowBackActive = computed(() => detail.fuzzFlow?.phase === 'rebuilding');
    const fuzzStage = computed(() => {
      const flow = detail.fuzzFlow;
      const phase = flow?.phase || '';
      const driver = flow?.driver_id ? `driver ${flow.driver_id} / v${flow.driver_seq || 0}` : `driver v${flow?.driver_seq || 0}`;
      let stageDetail = '';
      if (!flow) stageDetail = detail.fuzzStageStatus === 'running' ? '等待流程状态' : '';
      else if (phase === 'rebuilding' || phase === 'starting' || phase === 'restarting') stageDetail = flow.message || flowPhaseLabels[phase] || '';
      else stageDetail = `${driver} 持续运行`;
      const baseStage = activeStageDefs.value.find(stage => stage.id === 'fuzzing') || stageDefs[6];
      return {
        ...baseStage,
        status: detail.fuzzStageStatus || stageStatusMap.value.fuzzing || 'pending',
        detail: stageDetail,
        result: ''
      };
    });
    const analysisStage = computed(() => {
      const flow = detail.fuzzFlow;
      const failed = flow?.status === 'failed';
      const status = failed ? 'failed' : flowActive.value ? 'running' : flow?.last_result?.error ? 'warning' : 'pending';
      const phase = flow?.phase || '';
      let stageDetail = '';
      if (!flow) stageDetail = detail.fuzzStageStatus === 'running' ? '等待流程状态' : '进入 fuzzing 后启用';
      else if (detail.status !== 'running' && phase && phase !== 'fuzzing') stageDetail = `任务已${statusLabels[detail.status] || detail.status}，上次停在：${flowPhaseLabels[phase] || phase}`;
      else stageDetail = flowPhaseLabels[phase] || flow.message || '等待下一轮分析';
      const last = flow?.last_result;
      let result = '';
      if (last?.error) result = `上轮失败：${last.error}`;
      else if (last) result = last.needs_update ? `第 ${last.iteration} 轮已修改并${last.regenerated ? '完成重建' : '等待重建'}` : `第 ${last.iteration} 轮完成，无需修改`;
      return {
        id: 'fuzz_analysis',
        name: 'LLM 优化分析',
        owner: 'Codex CLI',
        index: '↻',
        status,
        detail: stageDetail,
        result
      };
    });
    const flowRows = computed(() =>
      [...(detail.fuzzFlowHistory || [])].reverse().map(item => {
        const outcome = item.error ? '分析失败' : item.needs_update ? (item.regenerated ? '已修改并重建' : '已修改') : item.plateau_reached ? '平台期·未修改' : '未到平台期';
        const duration = item.duration_seconds ? `${Math.max(0, item.duration_seconds).toFixed(1)}s` : '-';
        return {
          ...item,
          driver: item.driver_id ? `d${item.driver_id}/v${item.seq || 0}` : `v${item.seq || 0}`,
          outcome,
          summary: item.error || item.analysis || `耗时 ${duration}`
        };
      })
    );
    const detailResumable = computed(() => ['stopped', 'interrupted', 'failed'].includes(detail.status));
    const canTriggerFuzz = computed(() => {
      const phase = detail.fuzzFlow?.phase;
      const analysisBusy = phase && phase !== 'fuzzing';
      return detail.status === 'running' && detail.fuzzStageStatus === 'running' && !analysisBusy && !detailActionBusy.trigger;
    });
    const sortedCrashQueue = computed(() =>
      [...(detail.crashQueue || [])].sort((a, b) => {
        if (a.status === 'running' && b.status !== 'running') return -1;
        if (a.status !== 'running' && b.status === 'running') return 1;
        return (a.position || 0) - (b.position || 0);
      })
    );
    const uniqueCrashAllItems = computed(() => detail.uniqueCrashes || []);
    const uniqueCrashFilterOptions = computed(() => ({
      crash: buildUniqueCrashFilterOptions(uniqueCrashAllItems.value, 'crash'),
      status: buildUniqueCrashFilterOptions(uniqueCrashAllItems.value, 'status'),
      type: buildUniqueCrashFilterOptions(uniqueCrashAllItems.value, 'type')
    }));
    const uniqueCrashItems = computed(() => filterUniqueCrashItems(uniqueCrashAllItems.value, uniqueCrashFilters.selections));
    const uniqueCrashTotalCount = computed(() => uniqueCrashAllItems.value.length);
    const selectedCrashFixItems = computed(() => {
      const keys = selectedCrashFixKeys.value;
      return uniqueCrashItems.value.filter(item => keys.has(uniqueCrashKey(item)));
    });
    const selectedCrashDeleteItems = computed(() => {
      const keys = selectedCrashDeleteKeys.value;
      return uniqueCrashItems.value.filter(item => keys.has(uniqueCrashKey(item)));
    });
    const selectedCrashFixGroup = computed(() => {
      const first = selectedCrashFixItems.value[0];
      if (!first) return '';
      return crashFixGroup(first);
    });
    const uniqueCrashSelectionMode = computed(() => crashFixMode.value || crashDeleteMode.value);
    const crashFixSelectionCount = computed(() => selectedCrashFixItems.value.length);
    const crashDeleteSelectionCount = computed(() => selectedCrashDeleteItems.value.length);
    const uniqueCrashRepairableCount = computed(() => uniqueCrashItems.value.filter(item => crashFixEligible(item)).length);
    const snapshotRows = computed(() => detail.snapshots || []);
    const snapshotsMulti = computed(() => snapshotRows.value.some(snapshot => snapshot.driver_id));
    const crashReportCards = computed(() =>
      buildCrashReportCards(detail.crashReport.reports, detail.crashReport.focusFile)
    );
    const coverageData = computed(() => detail.coverage.data || null);
    const coverageIsMulti = computed(() => coverageData.value?.mode === 'multi');
    const coverageTargets = computed(() =>
      [...(coverageData.value?.targets || [])].sort((a, b) => {
        const driverDelta = Number(a.driver_id || 0) - Number(b.driver_id || 0);
        if (driverDelta !== 0) return driverDelta;
        return Number(a.seq || 0) - Number(b.seq || 0);
      })
    );
    const coverageTotalMeta = computed(() => {
      const data = coverageData.value;
      if (data?.available && data.timestamp) return `更新于 ${new Date(data.timestamp).toLocaleTimeString()}`;
      if (data?.timestamp) return '等待覆盖采集';
      return '等待采集';
    });
    const coverageStats = computed(() => {
      const data = coverageData.value;
      if (!data?.available) return [];
      const summary = data.coverage?.summary || {};
      return [
        {cls: 'full', num: summary.full_functions || 0, label: '完全覆盖函数'},
        {cls: 'partial', num: summary.partial_functions || 0, label: '部分覆盖函数'},
        {cls: '', num: summary.executed_functions || 0, label: '已执行函数'},
        {cls: '', num: data.seed_count || 0, label: 'corpus seed'}
      ];
    });
    const coveragePartials = computed(() =>
      sortedCoverageFunctions(coverageData.value?.coverage?.partial || []).map(fn => ({
        ...fn,
        branchCount: (fn.uncovered_branches || []).length,
        meta: `${(fn.file || '').split('/').pop()} · 调用 ${fn.entry_count || 0} 次`
      }))
    );
    const apiCoverage = computed(() => coverageData.value?.api_coverage || null);
    const apiCoverageRows = computed(() =>
      [...(apiCoverage.value?.apis || [])]
        .map(api => ({
          ...api,
          drivers: [...(api.drivers || [])].sort((a, b) => Number(a.driver_id || 0) - Number(b.driver_id || 0)),
          headerName: apiHeaderName(api.header)
        }))
        .sort(compareAPICoverageRows)
    );
    const apiCoverageMeta = computed(() => {
      const report = apiCoverage.value;
      if (!report?.available) return '等待 API 数据';
      return `${report.covered_apis || 0}/${report.total_apis || 0} · ${apiCoveragePercent(report)}`;
    });
    const driverSchedule = computed(() =>
      buildDriverSchedule(coverageData.value, coverageTargets.value, nowMs.value, coverageReceivedAtMs.value)
    );
    const coverageDriverMeta = computed(() => {
      const data = coverageData.value;
      if (!data || data.mode !== 'multi') return '等待调度';
      const {targets, queued} = schedulerLists(data);
      return `运行 ${data.active_targets || 0}/${targets.length} · queued ${queued.length}`;
    });
    const selectedCoverageTarget = computed(() =>
      findCoverageTarget(detail.coverageDetail.driverId, detail.coverageDetail.seq)
    );
    const driverCoverageTitle = computed(() => {
      const driverId = detail.coverageDetail.driverId || '-';
      const seq = Number(detail.coverageDetail.seq || 0);
      return seq > 0 ? `子 driver d${driverId}/v${seq} 覆盖详情` : `子 driver d${driverId} 覆盖详情`;
    });
    const driverCoverageMeta = computed(() => {
      const target = selectedCoverageTarget.value;
      if (!target) return [];
      const summary = target.summary || {};
      return [
        `状态：${targetStatusLabel(target.status)}`,
        `版本：v${target.seq || 0}`,
        `corpus seed：${target.seed_count || 0}`,
        `已执行函数：${summary.executed_functions || 0}`,
        `完全覆盖函数：${summary.full_functions || 0}`,
        `部分覆盖函数：${summary.partial_functions || 0}`,
        `未覆盖分支：${target.uncovered_count || 0}`
      ];
    });
    const driverGraphGroups = computed(() =>
      graphGroupsForTarget(selectedCoverageTarget.value, detail.coverageDetail.sourceData, detail.coverageDetail.sourceStatus === 'loading')
    );
    const driverGraphNote = computed(() =>
      detail.coverageDetail.sourceData ? '函数块按文件和源码行号顺序连接；颜色表示覆盖状态' : '正在加载源码块…'
    );
    const driverFunctionSections = computed(() => {
      const cov = selectedCoverageTarget.value?.coverage || {};
      return [
        {title: '完全覆盖函数', kind: 'full', functions: sortedCoverageFunctions(cov.full || [])},
        {title: '部分覆盖函数', kind: 'partial', functions: sortedCoverageFunctions(cov.partial || [])}
      ];
    });
    const diffLines = computed(() => {
      const diff = String(detail.snapshotDiff.diff || '').replace(/\n$/, '');
      if (!diff.trim()) return [];
      return diff.split('\n').map(text => {
        let className = '';
        if (text.startsWith('diff ') || text.startsWith('--- ') || text.startsWith('+++ ')) className = 'file';
        else if (text.startsWith('@@')) className = 'hunk';
        else if (text.startsWith('+')) className = 'added';
        else if (text.startsWith('-')) className = 'removed';
        return {text, className};
      });
    });

    async function responseJSON(response, fallbackMessage) {
      let result = {};
      try {
        result = await response.json();
      } catch (_) {
        result = {};
      }
      if (!response.ok) throw new Error(result.error || fallbackMessage);
      return result;
    }

    async function loadTasks() {
      if (tasksLoading.value) return;
      tasksLoading.value = true;
      try {
        const response = await fetch('/api/runs');
        const result = await responseJSON(response, 'Task 列表读取失败');
        tasks.value = Array.isArray(result) ? result : [];
      } catch (error) {
        const target = activeMainView.value === 'dashboard' ? 'dashboard' : 'list';
        setMessage(target, error.message || 'Task 列表读取失败');
      } finally {
        tasksLoading.value = false;
      }
    }

    async function loadOverview() {
      if (overviewLoading.value) return;
      overviewLoading.value = true;
      try {
        const response = await fetch('/api/overview');
        overview.value = await responseJSON(response, 'Dashboard 汇总读取失败');
        overviewFallback.value = false;
        messages.dashboard = '';
      } catch (error) {
        overview.value = overviewFromRuns(tasks.value);
        overviewFallback.value = true;
        if (activeMainView.value === 'dashboard') {
          messages.dashboard = `${error.message || 'Dashboard 汇总读取失败'}，已使用任务列表降级统计。`;
        }
      } finally {
        overviewLoading.value = false;
      }
    }

    async function refreshTaskData(includeOverview = activeMainView.value === 'dashboard') {
      await loadTasks();
      if (includeOverview) await loadOverview();
    }

    function setMainView(view, taskId = selectedTaskId.value) {
      activeMainView.value = view || 'dashboard';
      selectedTaskId.value = taskId || '';
      if (view === 'detail' && taskId) detail.id = taskId;
      else if (view !== 'detail') stopDetailPolling();
    }

    function navigate(view) {
      if (view === 'detail' && selectedTaskId.value) {
        router.push({name: 'task-detail', params: {taskId: selectedTaskId.value, tab: detail.activeTab || 'overview'}});
        return;
      }
      router.push({name: view === 'tasks' ? 'tasks' : 'dashboard'});
    }

    function openTask(id) {
      if (!id) return;
      router.push({name: 'task-detail', params: {taskId: id, tab: 'overview'}});
    }

    function openIssue(issue) {
      if (!issue?.task_id) return;
      router.push({
        name: 'task-detail',
        params: {taskId: issue.task_id, tab: 'crashes'},
        query: {
          report: Number(issue.seq || 0),
          driver: Number(issue.driver_id || 0),
          file: issue.file || ''
        }
      });
    }

    function pathPickerState(field) {
      if (!createForm.pathPickers[field]) {
        createForm.pathPickers[field] = {
          open: false,
          loading: false,
          error: '',
          path: '',
          entries: []
        };
      }
      return createForm.pathPickers[field];
    }

    function closePathPickers(exceptField = '') {
      Object.entries(createForm.pathPickers).forEach(([field, state]) => {
        if (field !== exceptField) state.open = false;
      });
    }

    function pathLooksBrowsable(value) {
      const text = String(value || '').trim();
      return text.length > 0 && (text.startsWith('/') || text.startsWith('~') || text.includes('/'));
    }

    async function browsePath(pathValue) {
      const params = new URLSearchParams();
      const path = String(pathValue || '').trim();
      if (path) params.set('path', path);
      const url = `/api/browse${params.toString() ? '?' + params.toString() : ''}`;
      if (pathPickerCache.has(url)) return pathPickerCache.get(url);
      const response = await fetch(url);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || '无法读取路径');
      pathPickerCache.set(url, data);
      window.setTimeout(() => pathPickerCache.delete(url), 3000);
      return data;
    }

    async function openPathPicker(field, pathValue = createForm.values[field] || '') {
      const state = pathPickerState(field);
      closePathPickers(field);
      state.open = true;
      state.loading = true;
      state.error = '';
      try {
        const data = await browsePath(pathValue);
        state.path = data.path || '';
        state.entries = Array.isArray(data.entries) ? data.entries : [];
      } catch (error) {
        state.path = '';
        state.entries = [];
        state.error = error.message || '无法读取路径';
      } finally {
        state.loading = false;
      }
    }

    function togglePathPicker(field) {
      const state = pathPickerState(field);
      if (state.open) {
        state.open = false;
        return;
      }
      openPathPicker(field);
    }

    function onPathInput(field) {
      window.clearTimeout(pathPickerDebounce.get(field));
      const value = createForm.values[field];
      if (!pathLooksBrowsable(value)) return;
      pathPickerDebounce.set(field, window.setTimeout(() => openPathPicker(field, value), 350));
    }

    function selectCurrentPath(field) {
      const state = pathPickerState(field);
      createForm.values[field] = state.path || '';
      state.open = false;
    }

    function selectPathEntry(field, entry) {
      if (!entry) return;
      createForm.values[field] = entry.path || '';
      if (entry.is_dir) openPathPicker(field, entry.path);
      else pathPickerState(field).open = false;
    }

    function setCreateDefaults(defaults = {}) {
      Object.keys(createForm.values).forEach(key => {
        if (!Object.prototype.hasOwnProperty.call(defaults, key)) return;
        const value = defaults[key];
        if (typeof createForm.values[key] === 'boolean') createForm.values[key] = Boolean(value);
        else if (typeof createForm.values[key] === 'number') createForm.values[key] = Math.max(1, Number(value) || 1);
        else createForm.values[key] = value ?? '';
      });
    }

    async function loadCreateDefaults() {
      try {
        const response = await fetch('/api/defaults');
        const defaults = await response.json();
        if (!response.ok) throw new Error(defaults.error || '读取默认配置失败');
        setCreateDefaults(defaults);
      } catch (error) {
        createForm.message = '读取默认配置失败：' + error.message;
      }
    }

    function createRequestBody() {
      const value = key => String(createForm.values[key] ?? '').trim();
      const numberValue = key => Number(createForm.values[key]) || 0;
      return {
        repository_url: value('repository_url'),
        ref: value('ref'),
        workspace: value('workspace'),
        promefuzz: value('promefuzz'),
        promefuzz_config: value('promefuzz_config'),
        python: value('python'),
        pool_size: numberValue('pool_size'),
        jobs: numberValue('jobs'),
        max_fuzz_drivers: numberValue('max_fuzz_drivers'),
        codex_command: value('codex_command'),
        codex_model: value('codex_model'),
        codex_profile: value('codex_profile'),
        resume: Boolean(createForm.values.resume),
        verbose: Boolean(createForm.values.verbose),
        stop_after: value('stop_after')
      };
    }

    async function submitCreateTask() {
      if (createForm.submitting) return;
      createForm.submitting = true;
      createForm.message = '正在创建 Task…';
      try {
        const response = await fetch('/api/runs', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(createRequestBody())
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || '任务创建失败');
        closeCreateModal();
        setMessage(activeMainView.value === 'dashboard' ? 'dashboard' : 'list', `Task ${result.id} 已创建，请在 Tasks 中启动。`);
        await refreshTaskData();
      } catch (error) {
        createForm.message = error.message;
      } finally {
        createForm.submitting = false;
      }
    }

    function openCreateModal() {
      createModalOpen.value = true;
      createForm.message = '填写运行配置后创建 Task；创建后需在列表中手动点击“开始”。';
      nextTick(() => {
        document.getElementById('repository_url')?.focus();
      });
    }

    function closeCreateModal() {
      createModalOpen.value = false;
      closePathPickers();
    }

    function handleEscape(event) {
      if (event.key !== 'Escape') return;
      if (detail.coverageDetail.visible) closeDriverCoverage();
      else if (createModalOpen.value) closeCreateModal();
    }

    function setDetail(patch = {}) {
      if (!patch || typeof patch !== 'object') return;
      if (Object.prototype.hasOwnProperty.call(patch, 'id')) {
        detail.id = patch.id || '';
        selectedTaskId.value = detail.id;
      }
      if (Object.prototype.hasOwnProperty.call(patch, 'name')) detail.name = patch.name || 'Task 详情';
      if (Object.prototype.hasOwnProperty.call(patch, 'repo')) detail.repo = patch.repo || '';
      if (Object.prototype.hasOwnProperty.call(patch, 'taskKind')) detail.taskKind = patch.taskKind || '';
      if (Object.prototype.hasOwnProperty.call(patch, 'parentTaskId')) detail.parentTaskId = patch.parentTaskId || '';
      if (Object.prototype.hasOwnProperty.call(patch, 'originDriverId')) detail.originDriverId = Number(patch.originDriverId || 0);
      if (Object.prototype.hasOwnProperty.call(patch, 'originDriverSeq')) detail.originDriverSeq = Number(patch.originDriverSeq || 0);
      if (Object.prototype.hasOwnProperty.call(patch, 'originCrashes')) detail.originCrashes = Array.isArray(patch.originCrashes) ? patch.originCrashes : [];
      if (Object.prototype.hasOwnProperty.call(patch, 'status')) detail.status = patch.status || '';
      if (Object.prototype.hasOwnProperty.call(patch, 'statusText')) detail.statusText = patch.statusText || '未启动';
      if (Object.prototype.hasOwnProperty.call(patch, 'message')) detail.message = patch.message || '';
      if (Object.prototype.hasOwnProperty.call(patch, 'meta')) detail.meta = patch.meta || '尚未选择任务';
      if (Object.prototype.hasOwnProperty.call(patch, 'activeTab')) detail.activeTab = patch.activeTab || 'overview';
      if (Object.prototype.hasOwnProperty.call(patch, 'stages')) setDetailStages(patch.stages);
      if (Object.prototype.hasOwnProperty.call(patch, 'fuzzStageStatus')) detail.fuzzStageStatus = patch.fuzzStageStatus || 'pending';
      if (Object.prototype.hasOwnProperty.call(patch, 'fuzzFlow')) {
        detail.fuzzFlow = patch.fuzzFlow || null;
        if (detailActionBusy.trigger && detail.fuzzFlow?.phase && detail.fuzzFlow.phase !== 'fuzzing') {
          detailActionBusy.trigger = false;
        }
      }
      if (Object.prototype.hasOwnProperty.call(patch, 'fuzzFlowHistory')) detail.fuzzFlowHistory = Array.isArray(patch.fuzzFlowHistory) ? patch.fuzzFlowHistory : [];
      if (Object.prototype.hasOwnProperty.call(patch, 'crashQueue')) setCrashQueue(patch.crashQueue);
      if (Object.prototype.hasOwnProperty.call(patch, 'uniqueCrashes')) setUniqueCrashes(patch.uniqueCrashes);
      if (Object.prototype.hasOwnProperty.call(patch, 'snapshots')) setSnapshots(patch.snapshots);
      if (Object.prototype.hasOwnProperty.call(patch, 'snapshotDiff')) setSnapshotDiff(patch.snapshotDiff);
      if (Object.prototype.hasOwnProperty.call(patch, 'crashReport')) setCrashReport(patch.crashReport);
      if (Object.prototype.hasOwnProperty.call(patch, 'coverage')) {
        const coveragePatch = patch.coverage;
        setCoverage(coveragePatch && typeof coveragePatch === 'object' && Object.prototype.hasOwnProperty.call(coveragePatch, 'data') ? coveragePatch.data : coveragePatch);
      }
      if (Object.prototype.hasOwnProperty.call(patch, 'coverageDetail')) setCoverageDetail(patch.coverageDetail);
      if (Object.prototype.hasOwnProperty.call(patch, 'codexEvents')) detail.codexEvents = Array.isArray(patch.codexEvents) ? patch.codexEvents : [];
      if (Object.prototype.hasOwnProperty.call(patch, 'logs')) detail.logs = Array.isArray(patch.logs) ? patch.logs : [];
    }

    function setDetailStages(stages) {
      detail.stages = Array.isArray(stages) ? stages : [];
      const fuzzing = detail.stages.find(stage => stage.id === 'fuzzing');
      detail.fuzzStageStatus = fuzzing?.status || detail.fuzzStageStatus || 'pending';
    }

    function setDetailTab(tab, syncRoute = true) {
      detail.activeTab = tab || 'overview';
      detail.snapshotDiff.visible = false;
      detail.crashReport.visible = false;
      if (detail.coverageDetail.visible) {
        coverageSourceRequest++;
        detail.coverageDetail.visible = false;
      }
      if (syncRoute && detail.id) {
        router.push({name: 'task-detail', params: {taskId: detail.id, tab: detail.activeTab}});
      }
    }

    async function resumeTask() {
      const id = detail.id;
      if (!id || detailActionBusy.resume) return;
      detailActionBusy.resume = true;
      detail.message = '正在恢复任务…';
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/start`, {method: 'POST'});
        await responseJSON(response, '任务恢复失败');
        await loadTaskDetail(id);
        await refreshTaskData(false);
      } catch (error) {
        if (detail.id === id) detail.message = error.message || '任务恢复失败';
      } finally {
        detailActionBusy.resume = false;
      }
    }

    async function cancelTask() {
      const id = detail.id;
      if (!id || detailActionBusy.cancel || !window.confirm('确认停止此 Task？之后可以从当前状态恢复。')) return;
      detailActionBusy.cancel = true;
      detail.message = '正在停止任务…';
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/cancel`, {method: 'POST'});
        await responseJSON(response, '停止失败');
        if (detail.id !== id) return;
        detail.status = 'stopping';
        detail.statusText = statusLabels.stopping;
        detail.message = 'Task 正在停止';
        await refreshTaskData(false);
      } catch (error) {
        if (detail.id === id) detail.message = error.message || '停止失败';
      } finally {
        detailActionBusy.cancel = false;
      }
    }

    async function triggerFuzz() {
      const id = detail.id;
      if (!id || detailActionBusy.trigger || !canTriggerFuzz.value) return;
      let submitted = false;
      detailActionBusy.trigger = true;
      detail.message = '正在触发 LLM 分析…';
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/trigger-fuzz`, {method: 'POST'});
        await responseJSON(response, '触发失败');
        submitted = true;
        if (detail.id === id) detail.message = '已触发 LLM 分析，等待流程启动…';
      } catch (error) {
        if (detail.id === id) detail.message = `触发失败: ${error.message || '未知错误'}`;
      } finally {
        if (!submitted) detailActionBusy.trigger = false;
      }
    }

    function setCrashQueue(items) {
      detail.crashQueue = Array.isArray(items) ? items : [];
    }

    function setUniqueCrashes(items) {
      detail.uniqueCrashes = Array.isArray(items) ? items : [];
      pruneUniqueCrashFilters();
      pruneCrashFixSelection();
    }

    function uniqueCrashEntry(item) {
      return item?.entry || {};
    }

    function uniqueCrashKey(item) {
      return `${item?.driver_id || 0}:${item?.seq || 0}:${uniqueCrashEntry(item).file || ''}`;
    }

    function uniqueCrashCreatedAt(item) {
      return formatLocalDateTime(item?.crash_created_at || uniqueCrashEntry(item).crash_created_at);
    }

    function uniqueCrashLastAnalysisAt(item) {
      return formatLocalDateTime(item?.last_analysis_at || uniqueCrashEntry(item).last_analysis_at);
    }

    function uniqueCrashFilterOptionsFor(column) {
      return uniqueCrashFilterOptions.value[column] || [];
    }

    function uniqueCrashFilterSelection(column) {
      return uniqueCrashFilters.selections[column];
    }

    function uniqueCrashFilterSelectedCount(column) {
      const options = uniqueCrashFilterOptionsFor(column);
      const selected = uniqueCrashFilterSelection(column);
      if (!selected) return options.length;
      return options.filter(option => selected.has(option.value)).length;
    }

    function uniqueCrashFilterAllSelected(column) {
      const options = uniqueCrashFilterOptionsFor(column);
      return uniqueCrashFilterSelectedCount(column) === options.length;
    }

    function uniqueCrashFilterOptionChecked(column, value) {
      const selected = uniqueCrashFilterSelection(column);
      return !selected || selected.has(value);
    }

    function uniqueCrashFilterSummary(column) {
      const options = uniqueCrashFilterOptionsFor(column);
      const selectedCount = uniqueCrashFilterSelectedCount(column);
      return selectedCount === options.length ? '全部' : `${selectedCount}/${options.length}`;
    }

    function uniqueCrashFilterActive(column) {
      return Boolean(uniqueCrashFilterSelection(column));
    }

    function uniqueCrashFilterIsOpen(column) {
      return uniqueCrashFilters.open === column;
    }

    function toggleUniqueCrashFilter(column) {
      uniqueCrashFilters.open = uniqueCrashFilters.open === column ? '' : column;
    }

    function closeUniqueCrashFilter() {
      uniqueCrashFilters.open = '';
    }

    function setUniqueCrashFilterAll(column, checked) {
      uniqueCrashFilters.selections[column] = checked ? null : new Set();
      pruneCrashFixSelection();
    }

    function setUniqueCrashFilterValue(column, value, checked) {
      const options = uniqueCrashFilterOptionsFor(column);
      let selected = uniqueCrashFilterSelection(column);
      selected = selected ? new Set(selected) : new Set(options.map(option => option.value));
      if (checked) selected.add(value);
      else selected.delete(value);
      const available = new Set(options.map(option => option.value));
      for (const existing of [...selected]) {
        if (!available.has(existing)) selected.delete(existing);
      }
      uniqueCrashFilters.selections[column] = selected.size === options.length ? null : selected;
      pruneCrashFixSelection();
    }

    function pruneUniqueCrashFilters() {
      for (const column of uniqueCrashFilterColumns) {
        const selected = uniqueCrashFilterSelection(column);
        if (!selected) continue;
        const available = new Set(uniqueCrashFilterOptionsFor(column).map(option => option.value));
        const next = new Set([...selected].filter(value => available.has(value)));
        uniqueCrashFilters.selections[column] = next.size === available.size ? null : next;
      }
    }

    function crashFixGroup(item) {
      return `${Number(item?.driver_id || 0)}:${Number(item?.seq || 0)}`;
    }

    function crashFixEligible(item) {
      const entry = uniqueCrashEntry(item);
      return entry.report_status === 'completed' &&
        entry.classification === 'library_bug' &&
        isOOBCrashType(entry.type);
    }

    function crashFixDisabledReason(item) {
      const entry = uniqueCrashEntry(item);
      if (!isOOBCrashType(entry.type)) return '仅支持 OOB 类型 crash';
      if (entry.report_status !== 'completed') return '需要先完成 LLM crash 分析';
      if (entry.classification !== 'library_bug') return '仅支持分类为库问题的 crash';
      if (selectedCrashFixGroup.value && selectedCrashFixGroup.value !== crashFixGroup(item)) return '一次只能修复同一 driver/version 的 crash';
      return '';
    }

    function canSelectCrashFix(item) {
      return crashFixEligible(item) && (!selectedCrashFixGroup.value || selectedCrashFixGroup.value === crashFixGroup(item));
    }

    function isCrashFixSelected(item) {
      return selectedCrashFixKeys.value.has(uniqueCrashKey(item));
    }

    function isCrashDeleteSelected(item) {
      return selectedCrashDeleteKeys.value.has(uniqueCrashKey(item));
    }

    function isUniqueCrashSelected(item) {
      return crashDeleteMode.value ? isCrashDeleteSelected(item) : isCrashFixSelected(item);
    }

    function setCrashFixSelected(item, checked) {
      if (checked && !canSelectCrashFix(item)) return;
      const next = new Set(selectedCrashFixKeys.value);
      const key = uniqueCrashKey(item);
      if (checked) next.add(key);
      else next.delete(key);
      selectedCrashFixKeys.value = next;
      crashFixMessage.value = '';
    }

    function setCrashDeleteSelected(item, checked) {
      const next = new Set(selectedCrashDeleteKeys.value);
      const key = uniqueCrashKey(item);
      if (checked) next.add(key);
      else next.delete(key);
      selectedCrashDeleteKeys.value = next;
      crashFixMessage.value = '';
    }

    function setUniqueCrashSelected(item, checked) {
      if (crashDeleteMode.value) {
        setCrashDeleteSelected(item, checked);
        return;
      }
      setCrashFixSelected(item, checked);
    }

    function canSelectUniqueCrash(item) {
      return crashDeleteMode.value || canSelectCrashFix(item);
    }

    function uniqueCrashSelectionDisabledReason(item) {
      return crashFixMode.value ? crashFixDisabledReason(item) : '';
    }

    function pruneCrashFixSelection() {
      if (!selectedCrashFixKeys.value.size) return;
      const live = new Set(uniqueCrashItems.value.map(item => uniqueCrashKey(item)));
      const next = new Set([...selectedCrashFixKeys.value].filter(key => live.has(key)));
      if (next.size !== selectedCrashFixKeys.value.size) selectedCrashFixKeys.value = next;
    }

    function pruneCrashDeleteSelection() {
      if (!selectedCrashDeleteKeys.value.size) return;
      const live = new Set(uniqueCrashItems.value.map(item => uniqueCrashKey(item)));
      const next = new Set([...selectedCrashDeleteKeys.value].filter(key => live.has(key)));
      if (next.size !== selectedCrashDeleteKeys.value.size) selectedCrashDeleteKeys.value = next;
    }

    function toggleCrashFixMode() {
      crashDeleteMode.value = false;
      selectedCrashDeleteKeys.value = new Set();
      crashFixMode.value = true;
      crashFixMessage.value = uniqueCrashRepairableCount.value
        ? '选择同一 driver/version 下需要修复的 OOB 库问题 crash。'
        : '当前没有满足条件的 OOB 库问题 crash。';
    }

    function cancelCrashFixSelection() {
      crashFixMode.value = false;
      crashFixMessage.value = '';
      selectedCrashFixKeys.value = new Set();
    }

    function toggleCrashDeleteMode() {
      crashFixMode.value = false;
      selectedCrashFixKeys.value = new Set();
      crashDeleteMode.value = true;
      crashFixMessage.value = uniqueCrashTotalCount.value
        ? '选择需要删除的 unique crash。'
        : '当前没有 unique crash。';
    }

    function cancelCrashDeleteSelection() {
      crashDeleteMode.value = false;
      crashFixMessage.value = '';
      selectedCrashDeleteKeys.value = new Set();
    }

    async function submitCrashFixTask() {
      const id = detail.id;
      if (!id || crashFixBusy.value) return;
      const items = selectedCrashFixItems.value;
      if (!items.length) {
        crashFixMessage.value = '请先选择要修复的 unique crash。';
        return;
      }
      const group = crashFixGroup(items[0]);
      if (items.some(item => crashFixGroup(item) !== group)) {
        crashFixMessage.value = '一次只能修复同一 driver/version 的 crash。';
        return;
      }
      const payload = {
        driver_id: Number(items[0].driver_id || 0),
        seq: Number(items[0].seq || 0),
        crashes: items.map(item => uniqueCrashEntry(item).file || '').filter(Boolean)
      };
      crashFixBusy.value = true;
      crashFixMessage.value = '正在创建修复子 task…';
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/crash-fix-tasks`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const child = await responseJSON(response, '创建修复子 task 失败');
        cancelCrashFixSelection();
        detail.message = `已创建修复子 task ${child.id || ''}`;
        await refreshTaskData(false);
        if (child.id) {
          router.push({name: 'task-detail', params: {taskId: child.id, tab: 'overview'}});
        }
      } catch (error) {
        crashFixMessage.value = error.message || '创建修复子 task 失败';
      } finally {
        crashFixBusy.value = false;
      }
    }

    async function deleteSelectedUniqueCrashes() {
      const id = detail.id;
      if (!id || crashDeleteBusy.value) return;
      const items = selectedCrashDeleteItems.value;
      if (!items.length) {
        crashFixMessage.value = '请先选择要删除的 unique crash。';
        return;
      }
      const count = items.length;
      if (!window.confirm(`确认删除 ${count} 个 unique crash？相关 LLM crash 报告也会被删除。`)) return;
      const deletingOpenReport = detail.crashReport.visible && items.some(item => {
        const entry = uniqueCrashEntry(item);
        return Number(item?.seq || 0) === Number(detail.crashReport.seq || 0) &&
          Number(item?.driver_id || 0) === Number(detail.crashReport.driverId || 0) &&
          (entry.file || '') === (detail.crashReport.focusFile || '');
      });
      const payload = {
        crashes: items.map(item => ({
          driver_id: Number(item?.driver_id || 0),
          seq: Number(item?.seq || 0),
          file: uniqueCrashEntry(item).file || ''
        })).filter(item => item.seq > 0 && item.file)
      };
      if (!payload.crashes.length) {
        crashFixMessage.value = '选中的 unique crash 缺少 snapshot 或文件名。';
        return;
      }
      crashDeleteBusy.value = true;
      crashFixMessage.value = '正在删除 unique crash…';
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/unique-crashes`, {
          method: 'DELETE',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const result = await responseJSON(response, '删除 unique crash 失败');
        selectedCrashDeleteKeys.value = new Set();
        crashDeleteMode.value = false;
        crashFixMessage.value = `已删除 ${result.deleted || payload.crashes.length} 个 unique crash。`;
        if (deletingOpenReport) {
          setCrashReport({visible: false, reports: [], focusFile: '', seq: 0, driverId: 0});
        }
        await refreshDetailData(id, ['uniqueCrashes', 'snapshots', 'crashQueue']);
        await refreshTaskData(true);
      } catch (error) {
        if (detail.id === id) crashFixMessage.value = error.message || '删除 unique crash 失败';
      } finally {
        crashDeleteBusy.value = false;
      }
    }

    function canAnalyzeUniqueCrash(item) {
      const status = uniqueCrashEntry(item).report_status || 'pending';
      return status !== 'queued' && status !== 'running' && status !== 'skipped';
    }

    function uniqueCrashAnalyzeLabel(item) {
      const status = uniqueCrashEntry(item).report_status || 'pending';
      if (status === 'queued') return '排队中';
      if (status === 'running') return '分析中';
      if (status === 'skipped') return '不可分析';
      return status === 'completed' ? '重新分析' : '分析';
    }

    function openUniqueCrash(item) {
      const entry = uniqueCrashEntry(item);
      router.push({
        name: 'task-detail',
        params: {taskId: detail.id, tab: 'crashes'},
        query: {
          report: Number(item?.seq || 0),
          driver: Number(item?.driver_id || 0),
          file: entry.file || ''
        }
      });
    }

    function analyzeUniqueCrash(item) {
      if (!canAnalyzeUniqueCrash(item)) return;
      const entry = uniqueCrashEntry(item);
      triggerCrashReportAnalysis(
        entry.file || '',
        Number(item?.seq || 0),
        Number(item?.driver_id || 0)
      );
    }

    function isCrashQueueBusy(itemId) {
      return crashQueueBusy.has(itemId);
    }

    async function removeCrashQueueItem(itemId) {
      const id = detail.id;
      if (!id || !itemId || crashQueueBusy.has(itemId)) return;
      crashQueueBusy.add(itemId);
      try {
        const params = new URLSearchParams({item_id: itemId});
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/crash-analysis-queue?${params.toString()}`, {method: 'DELETE'});
        await responseJSON(response, '移出 crash 分析队列失败');
        await refreshDetailData(id, ['crashQueue', 'uniqueCrashes']);
      } catch (error) {
        if (detail.id === id) detail.message = error.message || '移出 crash 分析队列失败';
      } finally {
        crashQueueBusy.delete(itemId);
      }
    }

    function setSnapshots(items) {
      detail.snapshots = Array.isArray(items) ? items : [];
    }

    function setSnapshotDiff(patch = {}) {
      if (!patch || typeof patch !== 'object') return;
      detail.snapshotDiff = {...detail.snapshotDiff, ...patch};
    }

    function setCrashReport(patch = {}) {
      if (!patch || typeof patch !== 'object') return;
      const next = {...detail.crashReport, ...patch};
      if (Object.prototype.hasOwnProperty.call(patch, 'reports')) {
        next.reports = Array.isArray(patch.reports) ? patch.reports : [];
      }
      detail.crashReport = next;
      nextTick(() => {
        if (!detail.crashReport.visible) return;
        document.getElementById('crashReportView')?.scrollIntoView({behavior: 'smooth', block: 'start'});
        if (detail.crashReport.focusFile) {
          document.querySelector('.crash-report-card.focused')?.scrollIntoView({behavior: 'smooth', block: 'center'});
        }
      });
    }

    function setCoverage(data) {
      detail.coverage.data = data || null;
      coverageReceivedAtMs.value = data ? Date.now() : 0;
      if (detail.coverageDetail.visible) refreshDriverCoverageSource();
    }

    function stopDetailPolling() {
      detailPollingVersion++;
      detailPollTimers.forEach(timer => window.clearInterval(timer));
      detailPollTimers.clear();
    }

    async function loadDetailResource(resource, id = detail.id, pollingVersion = detailPollingVersion) {
      if (!id) return;
      const requestId = (detailResourceRequests.get(resource) || 0) + 1;
      detailResourceRequests.set(resource, requestId);
      const paths = {
        coverage: 'coverage',
        snapshots: 'snapshots',
        crashQueue: 'crash-analysis-queue',
        uniqueCrashes: 'unique-crashes'
      };
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/${paths[resource]}`);
        const data = await responseJSON(response, `${resource} 读取失败`);
        if (pollingVersion !== detailPollingVersion || requestId !== detailResourceRequests.get(resource) || detail.id !== id) return;
        if (resource === 'coverage') setCoverage(data);
        else if (resource === 'snapshots') setSnapshots(data);
        else if (resource === 'crashQueue') setCrashQueue(data.items || []);
        else if (resource === 'uniqueCrashes') setUniqueCrashes(data.crashes || []);
      } catch (_) {
        // Polling is best-effort; the next interval retries transient failures.
      }
    }

    async function refreshDetailData(id = detail.id, resources = ['coverage', 'snapshots', 'uniqueCrashes', 'crashQueue']) {
      if (!id || detail.id !== id) return;
      const version = detailPollingVersion;
      await Promise.all(resources.map(resource => loadDetailResource(resource, id, version)));
    }

    function startDetailPolling(id, status) {
      stopDetailPolling();
      if (!id || detail.id !== id || status === 'pending') return;
      const version = detailPollingVersion;
      refreshDetailData(id);
      const schedule = (resource, interval) => {
        detailPollTimers.set(resource, window.setInterval(() => loadDetailResource(resource, id, version), interval));
      };
      schedule('crashQueue', 5000);
      if (status === 'running' || status === 'stopping') {
        schedule('coverage', 15000);
        schedule('snapshots', 30000);
        schedule('uniqueCrashes', 15000);
      }
    }

    function closeEventStream() {
      if (!eventSource) return;
      eventSource.close();
      eventSource = null;
    }

    function stopTaskRuntime() {
      detailSelectionVersion++;
      diffRequestVersion++;
      crashReportRequestVersion++;
      pendingDetailFocus = null;
      closeEventStream();
      stopDetailPolling();
      coverageSourceRequest++;
      driverSourceCache.clear();
      detailActionBusy.trigger = false;
      cancelCrashFixSelection();
    }

    function setStageStatus(stageId, status) {
      if (!activeStageDefs.value.some(stage => stage.id === stageId)) return;
      const stages = [...(detail.stages || [])];
      const index = stages.findIndex(stage => stage.id === stageId);
      if (index >= 0) stages[index] = {...stages[index], status};
      else stages.push({id: stageId, status});
      setDetailStages(stages);
    }

    function flowResultAsHistory(result) {
      return {
        iteration: result.iteration,
        seq: result.driver_seq,
        driver_id: result.driver_id,
        trigger: result.trigger,
        analysis: result.analysis || '',
        plateau_reached: result.plateau_reached,
        needs_update: result.needs_update,
        regenerated: result.regenerated,
        error: result.error || '',
        started_at: result.started_at,
        finished_at: result.finished_at,
        duration_seconds: result.started_at && result.finished_at
          ? (new Date(result.finished_at) - new Date(result.started_at)) / 1000
          : 0
      };
    }

    function upsertFlowHistory(entry) {
      if (!entry?.iteration) return;
      const history = [...(detail.fuzzFlowHistory || [])];
      const index = history.findIndex(item => item.iteration === entry.iteration);
      if (index >= 0) history[index] = {...history[index], ...entry};
      else history.push(entry);
      history.sort((a, b) => a.iteration - b.iteration);
      detail.fuzzFlowHistory = history.slice(-50);
    }

    async function loadFuzzFlow(id = detail.id, selectionVersion = detailSelectionVersion) {
      if (!id) return;
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/fuzz-flow?limit=50`);
        const data = await responseJSON(response, 'Fuzz flow 读取失败');
        if (detail.id !== id || selectionVersion !== detailSelectionVersion) return;
        detail.fuzzFlowHistory = Array.isArray(data.history) ? data.history : [];
        detail.fuzzFlow = data.current || null;
        if (data.current?.last_result) upsertFlowHistory(flowResultAsHistory(data.current.last_result));
      } catch (_) {
        // Flow state is optional before fuzzing starts.
      }
    }

    function resetTaskDetail(id) {
      selectedTaskId.value = id;
      coverageReceivedAtMs.value = 0;
      detailActionBusy.resume = false;
      detailActionBusy.cancel = false;
      detailActionBusy.trigger = false;
      crashQueueBusy.clear();
      driverSourceCache.clear();
      setDetail({
        id,
        name: 'Task 详情',
        repo: '',
        taskKind: '',
        parentTaskId: '',
        originDriverId: 0,
        originDriverSeq: 0,
        originCrashes: [],
        status: '',
        statusText: '加载中',
        message: '',
        meta: '正在加载任务快照...',
        stages: [],
        fuzzStageStatus: 'pending',
        fuzzFlow: null,
        fuzzFlowHistory: [],
        crashQueue: [],
        uniqueCrashes: [],
        snapshots: [],
        snapshotDiff: {
          visible: false,
          title: 'Driver Diff',
          meta: '',
          status: 'idle',
          message: '正在加载 Driver 差异...',
          diff: ''
        },
        crashReport: {
          visible: false,
          title: 'Unique Crash 分析报告',
          meta: '',
          status: 'idle',
          message: '正在加载 crash 报告...',
          reports: [],
          focusFile: '',
          seq: 0,
          driverId: 0
        },
        coverage: {data: null},
        coverageDetail: {
          visible: false,
          driverId: 0,
          seq: 0,
          sourceData: null,
          sourceStatus: 'idle',
          sourceMessage: ''
        },
        codexEvents: [],
        logs: []
      });
      clearCodexEvents('正在加载任务事件');
      clearLogs('正在加载任务日志');
    }

    function showTaskDetail(id, options = {}) {
      if (!id) return;
      setMainView('detail', id);
      pendingDetailFocus = options.focus ? {
        taskId: id,
        kind: options.focus.kind || 'report',
        tab: options.tab || 'crashes',
        seq: Number(options.focus.seq || 0),
        driverId: Number(options.focus.driverId || 0),
        file: options.focus.file || ''
      } : null;
      setDetailTab(options.tab || 'overview', false);
      loadTaskDetail(id);
    }

    async function loadTaskDetail(id) {
      if (!id) return;
      const selectionVersion = ++detailSelectionVersion;
      closeEventStream();
      stopDetailPolling();
      resetTaskDetail(id);
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}`);
        const snapshot = await responseJSON(response, '任务快照读取失败');
        if (selectionVersion !== detailSelectionVersion || detail.id !== id) return;
        const repository = snapshot.request?.repository_url || '';
        const detailName = snapshot.request?.name || repository.split('/').filter(Boolean).pop()?.replace(/\.git$/, '') || id;
        setDetailStages(snapshot.stages || []);
        detail.name = detailName;
        detail.repo = repository;
        detail.taskKind = snapshot.task_kind || snapshot.request?.task_kind || '';
        detail.parentTaskId = snapshot.parent_task_id || snapshot.request?.parent_task_id || '';
        detail.originDriverId = Number(snapshot.origin_driver_id || snapshot.request?.origin_driver_id || 0);
        detail.originDriverSeq = Number(snapshot.origin_driver_seq || snapshot.request?.origin_driver_seq || 0);
        detail.originCrashes = Array.isArray(snapshot.origin_crashes) ? snapshot.origin_crashes : (snapshot.request?.origin_crashes || []);
        const parentMeta = detail.parentTaskId ? ` · parent: ${detail.parentTaskId}` : '';
        const originMeta = detail.originDriverId ? ` · origin d${detail.originDriverId}/v${detail.originDriverSeq || 0}` : '';
        detail.meta = `任务 ${id}${parentMeta}${originMeta} · workspace: ${snapshot.target_dir || ''}${snapshot.error ? ' · 错误: ' + snapshot.error : ''}`;
        detail.status = snapshot.status || '';
        detail.statusText = statusLabels[snapshot.status] || snapshot.status || '未启动';
        loadFuzzFlow(id, selectionVersion);
        if (snapshot.status === 'running' || snapshot.status === 'stopping') {
          connectEvents(id);
          startDetailPolling(id, snapshot.status);
        } else if (snapshot.status !== 'pending') {
          fetchTaskHistory(id, selectionVersion);
          startDetailPolling(id, snapshot.status);
        }
        await applyPendingDetailFocus(id, selectionVersion);
      } catch (error) {
        if (selectionVersion !== detailSelectionVersion || detail.id !== id) return;
        detail.status = 'failed';
        detail.statusText = '加载失败';
        detail.message = error.message || '任务快照读取失败';
      }
    }

    async function applyPendingDetailFocus(id, selectionVersion) {
      const focus = pendingDetailFocus;
      if (!focus || focus.taskId !== id) return;
      pendingDetailFocus = null;
      setDetailTab(focus.tab || 'crashes', false);
      if (focus.kind === 'coverage') {
        activateDriverCoverage(focus.driverId, focus.seq);
        await refreshDetailData(id, ['coverage']);
        if (selectionVersion !== detailSelectionVersion || detail.id !== id) return;
        return;
      }
      if (focus.kind === 'diff' && focus.seq > 1) {
        await loadSnapshotDiff(focus.seq, focus.driverId);
        return;
      }
      await refreshDetailData(id, ['crashQueue', 'uniqueCrashes']);
      if (selectionVersion !== detailSelectionVersion || detail.id !== id) return;
      if (focus.seq > 0) {
        await openCrashReports(focus.seq, focus.driverId, focus.file);
        return;
      }
      nextTick(() => document.getElementById('uniqueCrashPanel')?.scrollIntoView({behavior: 'smooth', block: 'start'}));
    }

    async function fetchTaskHistory(id, selectionVersion = detailSelectionVersion) {
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/history`);
        const entries = await responseJSON(response, '任务历史读取失败');
        if (selectionVersion !== detailSelectionVersion || detail.id !== id || !Array.isArray(entries) || entries.length === 0) return;
        appendLogLine('=== fuzzing 迭代历史 ===');
        entries.forEach(entry => {
          const timestamp = entry.started_at ? entry.started_at.slice(11, 19) : '--:--:--';
          const rebuild = entry.regenerated ? ' [rebuild]' : '';
          const analysis = entry.analysis ? entry.analysis.slice(0, 120) : '(无分析)';
          const driver = entry.driver_id ? `d${entry.driver_id}/v${entry.seq}` : `v${entry.seq}`;
          appendLogLine(`[${timestamp}] iter=${entry.iteration} ${driver}${rebuild} ${analysis}`);
        });
        appendLogLine(`=== 共 ${entries.length} 条迭代记录 ===`);
      } catch (_) {
        // History is supplemental; task detail remains usable without it.
      }
    }

    async function refreshSnapshot(id = detail.id) {
      if (!id) return;
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}`);
        const snapshot = await responseJSON(response, '任务快照读取失败');
        if (detail.id !== id) return;
        setDetailStages(snapshot.stages || []);
        detail.meta = `任务 ${snapshot.id || id} · workspace: ${snapshot.target_dir || ''}${snapshot.error ? ' · 错误: ' + snapshot.error : ''}`;
      } catch (_) {
        // The final run event already carries the authoritative status.
      }
    }

    function connectEvents(id) {
      closeEventStream();
      const source = new EventSource(`/api/runs/${encodeURIComponent(id)}/events`);
      eventSource = source;
      source.addEventListener('autofuzz', message => {
        if (detail.id !== id || eventSource !== source) return;
        try {
          handleRuntimeEvent(JSON.parse(message.data));
        } catch (error) {
          appendLogLine(`事件解析失败: ${error.message}`);
        }
      });
      source.onerror = () => {
        if (detail.id === id && eventSource === source && (detail.status === 'running' || detail.status === 'stopping')) {
          detail.message = '事件流连接中断，浏览器会自动重连。';
        }
      };
    }

    function handleRuntimeEvent(event) {
      if (event.kind === 'stage') {
        setStageStatus(event.stage, event.status);
        appendLogEvent(event);
        return;
      }
      if (event.kind === 'codex') {
        appendCodexEvent(event);
        return;
      }
      if (event.kind === 'fuzz_flow') {
        const flow = event.data || null;
        detail.fuzzFlow = flow;
        if (detailActionBusy.trigger && flow?.phase && flow.phase !== 'fuzzing') detailActionBusy.trigger = false;
        if (flow?.last_result && (flow.phase === 'fuzzing' || flow.status === 'failed')) {
          upsertFlowHistory(flowResultAsHistory(flow.last_result));
        }
        if (flow?.status === 'failed') detail.message = `LLM 优化分析失败：${flow.message || '见日志'}`;
        else if (flow?.phase === 'rebuilding') detail.message = 'LLM 已修改 driver，正在重建并重启 fuzz';
        else if (flow?.phase === 'fuzzing' && detail.status === 'running') detail.message = '持续 Fuzz 运行中，等待下一轮优化分析';
        return;
      }
      if (event.kind === 'log') {
        appendLogEvent(event);
        if (event.source === 'crash-analysis') {
          refreshDetailData(detail.id, ['crashQueue', 'uniqueCrashes']);
          if (/^crash analysis (completed|failed):/.test(event.message || '') && detail.status !== 'running' && detail.status !== 'stopping') {
            closeEventStream();
          }
        }
        return;
      }
      if (event.kind !== 'run') return;
      appendLogEvent(event);
      detail.status = event.status || detail.status;
      detail.statusText = statusLabels[event.status] || event.status || detail.statusText;
      if (['completed', 'failed', 'stopped', 'interrupted'].includes(event.status)) finishTaskUI(event.status);
    }

    function finishTaskUI(status) {
      detail.status = status;
      detail.statusText = statusLabels[status] || status;
      closeEventStream();
      startDetailPolling(detail.id, status);
      refreshSnapshot(detail.id);
      refreshTaskData(false);
    }

    async function loadSnapshotDiff(targetSeq, driverId = 0) {
      if (!detail.id || targetSeq <= 1) return;
      const id = detail.id;
      const requestVersion = ++diffRequestVersion;
      detail.crashReport.visible = false;
      setSnapshotDiff({
        visible: true,
        title: `${driverId ? `driver ${driverId} · ` : ''}v${targetSeq - 1} -> v${targetSeq} Driver 差异`,
        meta: `Task ${id} · 对比 target driver 源码`,
        status: 'loading',
        message: '正在加载 Driver 差异...',
        diff: ''
      });
      nextTick(() => document.getElementById('snapshotDiffView')?.scrollIntoView({behavior: 'smooth', block: 'start'}));
      try {
        const suffix = driverId ? `?driver_id=${encodeURIComponent(driverId)}` : '';
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/snapshots/${targetSeq}/diff${suffix}`);
        const result = await responseJSON(response, 'Driver diff 读取失败');
        if (requestVersion !== diffRequestVersion || detail.id !== id) return;
        setSnapshotDiff({
          title: `${result.driver_id ? `driver ${result.driver_id} · ` : ''}v${result.base_seq} -> v${result.target_seq} Driver 差异`,
          status: 'ready',
          message: '',
          diff: result.diff || ''
        });
      } catch (error) {
        if (requestVersion !== diffRequestVersion || detail.id !== id) return;
        setSnapshotDiff({status: 'error', message: error.message, diff: ''});
      }
    }

    async function openCrashReports(seq, driverId = 0, focusFile = '') {
      if (!detail.id || seq <= 0) return;
      const id = detail.id;
      const requestVersion = ++crashReportRequestVersion;
      detail.snapshotDiff.visible = false;
      setCrashReport({
        visible: true,
        title: `${driverId ? `driver ${driverId} · ` : ''}v${seq} Unique Crash 分析报告`,
        meta: `Task ${id} · 读取 snapshot 内 crash-reports/`,
        status: 'loading',
        message: '正在加载 crash 报告...',
        reports: [],
        focusFile,
        seq,
        driverId
      });
      try {
        const params = new URLSearchParams({seq: String(seq)});
        if (driverId) params.set('driver_id', String(driverId));
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/crash-reports?${params.toString()}`);
        const result = await responseJSON(response, 'Crash 报告读取失败');
        if (requestVersion !== crashReportRequestVersion || detail.id !== id) return;
        setCrashReport({
          visible: true,
          title: `${result.driver_id ? `driver ${result.driver_id} · ` : ''}v${result.seq} Unique Crash 分析报告`,
          meta: result.snapshot_dir || '',
          status: 'ready',
          message: '',
          reports: result.reports || [],
          focusFile,
          seq: result.seq || seq,
          driverId: result.driver_id || driverId
        });
      } catch (error) {
        if (requestVersion !== crashReportRequestVersion || detail.id !== id) return;
        setCrashReport({status: 'error', message: error.message, reports: [], focusFile, seq, driverId});
      }
    }

    async function triggerCrashReportAnalysis(file, seq = detail.crashReport.seq, driverId = detail.crashReport.driverId) {
      const id = detail.id;
      if (!id || !seq || !file) return;
      const focusFile = detail.crashReport.focusFile;
      const params = new URLSearchParams({seq: String(seq), file});
      if (driverId) params.set('driver_id', String(driverId));
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(id)}/crash-reports/analyze?${params.toString()}`, {method: 'POST'});
        await responseJSON(response, '启动 crash 分析失败');
        if (!eventSource) connectEvents(id);
        await refreshDetailData(id, ['crashQueue', 'uniqueCrashes']);
        if (detail.crashReport.visible && seq === detail.crashReport.seq && driverId === detail.crashReport.driverId) {
          await openCrashReports(seq, driverId, focusFile);
        }
      } catch (error) {
        if (detail.id === id) detail.message = error.message || '启动 crash 分析失败';
      }
    }

    function setCoverageDetail(patch = {}) {
      if (!patch || typeof patch !== 'object') return;
      detail.coverageDetail = {...detail.coverageDetail, ...patch};
    }

    function openSnapshotDiff(snapshot) {
      if (!snapshot || Number(snapshot.seq || 0) <= 1) return;
      router.push({
        name: 'task-detail',
        params: {taskId: detail.id, tab: 'snapshots'},
        query: {diff: Number(snapshot.seq || 0), driver: Number(snapshot.driver_id || 0)}
      });
    }

    function openSnapshotReports(snapshot) {
      if (!snapshot || Number(snapshot.unique_crash_count || 0) <= 0) return;
      router.push({
        name: 'task-detail',
        params: {taskId: detail.id, tab: 'crashes'},
        query: {report: Number(snapshot.seq || 0), driver: Number(snapshot.driver_id || 0)}
      });
    }

    function closeSnapshotDiff() {
      router.push({name: 'task-detail', params: {taskId: detail.id, tab: 'snapshots'}});
    }

    function closeCrashReport() {
      router.push({name: 'task-detail', params: {taskId: detail.id, tab: 'crashes'}});
    }

    function analyzeCrashReport(card) {
      if (!card?.canAnalyze) return;
      triggerCrashReportAnalysis(
        card.file || '',
        Number(detail.crashReport.seq || 0),
        Number(detail.crashReport.driverId || 0)
      );
    }

    function findCoverageTarget(driverId, seq = 0) {
      const id = Number(driverId || 0);
      const version = Number(seq || 0);
      if (id <= 0) return null;
      const matches = coverageTargets.value.filter(item => Number(item.driver_id || 0) === id);
      if (version > 0) return matches.find(item => Number(item.seq || 0) === version) || null;
      return [...matches].sort((a, b) => Number(b.seq || 0) - Number(a.seq || 0))[0] || null;
    }

    function driverSourceCacheKey(driverId, seq) {
      const target = findCoverageTarget(driverId, seq);
      const summary = target?.summary || {};
      return `${detail.id}:${driverId || 0}:v${target?.seq || seq || 0}:n${summary.executed_functions || 0}`;
    }

    async function refreshDriverCoverageSource() {
      const driverId = Number(detail.coverageDetail.driverId || 0);
      const seq = Number(detail.coverageDetail.seq || 0);
      if (!detail.id || !driverId || !detail.coverageDetail.visible) return;
      const requestId = ++coverageSourceRequest;
      const key = driverSourceCacheKey(driverId, seq);
      if (driverSourceCache.has(key)) {
        detail.coverageDetail.sourceData = driverSourceCache.get(key);
        detail.coverageDetail.sourceStatus = 'ready';
        detail.coverageDetail.sourceMessage = '';
        return;
      }
      detail.coverageDetail.sourceData = null;
      detail.coverageDetail.sourceStatus = 'loading';
      detail.coverageDetail.sourceMessage = '';
      const params = new URLSearchParams({driver_id: String(driverId)});
      if (seq > 0) params.set('seq', String(seq));
      try {
        const response = await fetch(`/api/runs/${encodeURIComponent(detail.id)}/coverage/function-sources?${params.toString()}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || '源码片段读取失败');
        if (
          requestId !== coverageSourceRequest ||
          Number(detail.coverageDetail.driverId || 0) !== driverId ||
          Number(detail.coverageDetail.seq || 0) !== seq
        ) return;
        driverSourceCache.set(key, data);
        detail.coverageDetail.sourceData = data;
        detail.coverageDetail.sourceStatus = 'ready';
        detail.coverageDetail.sourceMessage = '';
      } catch (error) {
        if (
          requestId !== coverageSourceRequest ||
          Number(detail.coverageDetail.driverId || 0) !== driverId ||
          Number(detail.coverageDetail.seq || 0) !== seq
        ) return;
        const data = {available: false, error: error.message, functions: []};
        driverSourceCache.set(key, data);
        detail.coverageDetail.sourceData = data;
        detail.coverageDetail.sourceStatus = 'error';
        detail.coverageDetail.sourceMessage = error.message;
      }
    }

    function openDriverCoverage(driverId, seq = 0) {
      const target = findCoverageTarget(driverId, seq);
      if (!hasDriverCoverageDetails(target)) return;
      router.push({
        name: 'driver-coverage',
        params: {taskId: detail.id, driverId: Number(driverId || 0), seq: Number(target.seq || seq || 0)}
      });
    }

    function activateDriverCoverage(driverId, seq = 0) {
      detail.coverageDetail = {
        visible: true,
        driverId: Number(driverId || 0),
        seq: Number(seq || 0),
        sourceData: null,
        sourceStatus: 'idle',
        sourceMessage: ''
      };
      refreshDriverCoverageSource();
    }

    function closeDriverCoverage() {
      router.push({name: 'task-detail', params: {taskId: detail.id, tab: 'coverage'}});
    }

    function snapDeltaClass(value) {
      const n = Number(value || 0);
      if (n > 0) return 'pos';
      if (n < 0) return 'neg';
      return 'zero';
    }

    function snapDeltaStr(value) {
      const n = Number(value || 0);
      if (n === 0) return '';
      return n > 0 ? `+${n}` : `${n}`;
    }

    function normalizeCodexEvent(event) {
      const data = event?.data || {};
      const item = data.item || {};
      const stage = event?.stage || '-';
      const id = `${Date.now()}:${Math.random().toString(36).slice(2)}`;
      if (item.type === 'command_execution') {
        const command = codexCommandText(item) || '(empty command)';
        const statusParts = [];
        if (item.status) statusParts.push(String(item.status));
        if (data.type && data.type !== item.status) statusParts.push(String(data.type));
        if (item.exit_code != null) statusParts.push(`exit ${item.exit_code}`);
        return {
          id,
          kind: 'command',
          stage,
          command,
          preview: truncateText(command, CODEX_CMD_PREVIEW_LIMIT),
          status: statusParts.join(' · '),
          output: codexString(item.aggregated_output ?? item.output ?? item.stdout ?? item.stderr ?? '')
        };
      }
      if (item.type === 'reasoning') {
        return {id, kind: 'thinking', stage, text: codexItemText(item) || codexString(data)};
      }
      if (isCodexMessageItem(item)) {
        const role = String(item.type || '').includes('user') ? 'user' : 'agent';
        return {id, kind: 'message', stage, role, html: markdownToHtml(codexItemText(item) || '(empty message)')};
      }
      return {id, kind: 'raw', stage, label: data.type || item.type || 'Codex event', raw: codexString(data)};
    }

    function appendCodexEvent(event) {
      detail.codexEvents.push(normalizeCodexEvent(event));
      if (detail.codexEvents.length > 800) detail.codexEvents = detail.codexEvents.slice(-800);
      nextTick(() => {
        if (codexEventsRef.value) codexEventsRef.value.scrollTop = codexEventsRef.value.scrollHeight;
      });
    }

    function clearCodexEvents(message) {
      detail.codexEvents = [];
      detail.codexEmpty = message || 'built / configured / fuzzing 阶段的 Codex JSONL 事件将在这里出现';
    }

    function appendLogEvent(event) {
      const source = `[${event?.stage || '-'} · ${event?.source || 'autofuzz'}]`;
      const message = event?.message || '';
      detail.logs.push({source, message});
      if (detail.logs.length > 2000) detail.logs = detail.logs.slice(-2000);
    }

    function appendLogLine(message) {
      detail.logs.push({source: '', message: message || ''});
      if (detail.logs.length > 2000) detail.logs = detail.logs.slice(-2000);
    }

    function clearLogs(message = '') {
      detail.logs = [];
      if (message) {
        detail.logs.push({source: '', message});
      }
    }

    function detailOptionsFromRoute() {
      if (isDriverCoverageRouteName(route.name)) {
        return {
          tab: 'coverage',
          focus: {
            kind: 'coverage',
            driverId: Number(route.params.driverId || 0),
            seq: Number(route.params.seq || 0)
          }
        };
      }
      const tab = String(route.params.tab || 'overview');
      const driverId = Number(route.query.driver || 0);
      const diffSeq = Number(route.query.diff || 0);
      if (diffSeq > 1) {
        return {tab: 'snapshots', focus: {kind: 'diff', seq: diffSeq, driverId}};
      }
      const reportSeq = Number(route.query.report || 0);
      if (reportSeq > 0) {
        return {
          tab: 'crashes',
          focus: {kind: 'report', seq: reportSeq, driverId, file: String(route.query.file || '')}
        };
      }
      return {tab};
    }

    function syncRoute() {
      if (route.name === 'dashboard') {
        if (activeMainView.value !== 'dashboard') stopTaskRuntime();
        setMainView('dashboard', '');
        refreshTaskData(true);
        return;
      }
      if (route.name === 'tasks') {
        if (activeMainView.value !== 'tasks') stopTaskRuntime();
        setMainView('tasks', '');
        loadTasks();
        return;
      }
      if (route.name !== 'task-detail' && !isDriverCoverageRouteName(route.name)) return;
      const id = String(route.params.taskId || '');
      if (!id) return;
      const options = detailOptionsFromRoute();
      if (activeMainView.value !== 'detail' || detail.id !== id) {
        showTaskDetail(id, options);
        return;
      }
      setDetailTab(options.tab, false);
      if (options.focus) {
        pendingDetailFocus = {taskId: id, tab: options.tab, ...options.focus};
        applyPendingDetailFocus(id, detailSelectionVersion);
      }
    }

    watch(uniqueCrashItems, () => {
      pruneCrashFixSelection();
      pruneCrashDeleteSelection();
    });
    watch(() => route.fullPath, syncRoute, {immediate: true});

    onMounted(() => {
      document.addEventListener('keydown', handleEscape);
      countdownTimer = window.setInterval(() => {
        nowMs.value = Date.now();
      }, 1000);
      taskPollTimer = window.setInterval(() => {
        if (activeMainView.value !== 'detail') loadTasks();
      }, 5000);
      overviewPollTimer = window.setInterval(() => {
        if (activeMainView.value === 'dashboard') loadOverview();
      }, 10000);
      loadCreateDefaults();
      refreshTaskData(true);
    });

    onUnmounted(() => {
      document.removeEventListener('keydown', handleEscape);
      if (countdownTimer) window.clearInterval(countdownTimer);
      if (taskPollTimer) window.clearInterval(taskPollTimer);
      if (overviewPollTimer) window.clearInterval(overviewPollTimer);
      stopTaskRuntime();
    });

    function isTaskBusy(id) {
      return taskBusy.has(id);
    }

    async function runTaskAction(id, message, request, successMessage) {
      if (!id || taskBusy.has(id)) return;
      taskBusy.add(id);
      messages.list = message;
      try {
        await request();
        messages.list = successMessage;
        await refreshTaskData(false);
      } catch (error) {
        messages.list = error.message || 'Task 操作失败';
      } finally {
        taskBusy.delete(id);
      }
    }

    async function startTask(id) {
      await runTaskAction(
        id,
        '正在启动 Task…',
        async () => {
          const response = await fetch(`/api/runs/${encodeURIComponent(id)}/start`, {method: 'POST'});
          await responseJSON(response, 'Task 启动失败');
        },
        `Task ${id} 已启动`
      );
    }

    async function stopTask(id) {
      if (!window.confirm('确认停止此 Task？之后可以从当前状态恢复。')) return;
      await runTaskAction(
        id,
        '正在停止 Task…',
        async () => {
          const response = await fetch(`/api/runs/${encodeURIComponent(id)}/cancel`, {method: 'POST'});
          await responseJSON(response, 'Task 停止失败');
        },
        `Task ${id} 正在停止`
      );
    }

    async function removeTask(id) {
      if (!window.confirm('确认删除此任务记录？(不会删除工作目录数据)')) return;
      await runTaskAction(
        id,
        '正在删除 Task…',
        async () => {
          const response = await fetch(`/api/runs/${encodeURIComponent(id)}`, {method: 'DELETE'});
          await responseJSON(response, '删除失败');
        },
        `Task ${id} 已删除`
      );
    }

    function setMessage(target, message) {
      if (target === 'dashboard' || target === 'list') messages[target] = message || '';
    }

    const controller = {
      activeMainView,
      abnormalTasks,
      analysisStage,
      canTriggerFuzz,
      analyzeCrashReport,
      analyzeUniqueCrash,
      branchCountsText,
      branchLocation,
      cancelTask,
      canAnalyzeUniqueCrash,
      closeCrashReport,
      closeDriverCoverage,
      closeSnapshotDiff,
      closePathPickers,
      codexEventsRef,
      createForm,
      createModalOpen,
      crashBadge: issue => crashReportBadge(issue.report_status || 'pending', issue.classification || ''),
      crashBadgeForEntry: entry => crashReportBadge(entry.report_status || 'pending', entry.classification || ''),
      crashDeleteBusy,
      crashDeleteMode,
      crashDeleteSelectionCount,
      crashFixBusy,
      crashFixDisabledReason,
      crashFixEligible,
      crashFixMessage,
      crashFixMode,
      crashFixSelectionCount,
      crashReportCards,
      coverageBranchLine,
      coverageData,
      coverageDriverMeta,
      coverageIsMulti,
      coveragePartials,
      apiCoverage,
      apiCoverageRows,
      apiCoverageMeta,
      apiDriverLabel,
      apiDriverTitle,
      driverSchedule,
      coverageStats,
      coverageTargets,
      coverageTotalMeta,
      detail,
      detailActionBusy,
      detailResumable,
      detailTabs,
      discoveredIssues,
      driverColumns,
      driverCoverageMeta,
      driverCoverageTitle,
      driverFunctionSections,
      driverGraphGroups,
      driverGraphNote,
      driverRowClass,
      diffLines,
      deleteSelectedUniqueCrashes,
      flowBackActive,
      flowForwardActive,
      flowRows,
      formatDate: formatLocalDateTime,
      fuzzStage,
      hasTaskDetail,
      isResumable: status => ['stopped', 'interrupted', 'failed'].includes(status),
      issueDriverLabel: issue => issue.driver_id ? `d${issue.driver_id}/v${issue.seq || '-'}` : `v${issue.seq || '-'}`,
      issueKey: issue => `${issue.task_id || ''}:${issue.driver_id || 0}:${issue.seq || 0}:${issue.file || ''}`,
      issueNote,
      isCrashQueueBusy,
      isCrashFixSelected,
      isTaskBusy,
      isUniqueCrashSelected,
      linearStages,
      messages,
      navigate,
      onPathInput,
      openCreateModal,
      openDriverCoverage,
      openIssue,
      openPathPicker,
      openTask,
      openSnapshotDiff,
      openSnapshotReports,
      openUniqueCrash,
      queueNote,
      queueDriverLabel: item => item.driver_id ? `d${item.driver_id}` : '未标注',
      queueTotal,
      recentIssues,
      recentTasks,
      removeTask,
      removeCrashQueueItem,
      pathPickerState,
      resumeTask,
      runningSidebarLabel,
      runningTasks,
      setDetailTab,
      shortTime: value => {
        if (!value) return '-';
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString();
      },
      startTask,
      selectCurrentPath,
      selectPathEntry,
      snapDeltaClass,
      snapDeltaStr,
      snapshotKey: snapshot => `${snapshot.driver_id || 0}:${snapshot.seq || 0}:${snapshot.timestamp || ''}`,
      snapshotRows,
      snapshotsMulti,
      statusClass: safeClass,
      statusColumns: statusColumnsView,
      statusLabel: status => statusLabels[status] || status || '-',
      targetStatusLabel,
      hasDriverCoverageDetails,
      stopTask,
      submitCrashFixTask,
      submitCreateTask,
      taskCounts,
      tasksLoading,
      tasks,
      topbarSubtitle,
      topbarTitle,
      triggerFuzz,
      totalTaskNote,
      sortedCrashQueue,
      uniqueCrashAnalyzeLabel,
      uniqueCrashRepairableCount,
      uniqueCrashDriverLabel: item => item.driver_id ? `d${item.driver_id}` : '未标注',
      uniqueCrashCreatedAt,
      uniqueCrashEntry,
      uniqueCrashFilterActive,
      uniqueCrashFilterAllSelected,
      uniqueCrashFilterIsOpen,
      uniqueCrashFilterOptionChecked,
      uniqueCrashFilterOptionsFor,
      uniqueCrashFilterSelectedCount,
      uniqueCrashFilterSummary,
      uniqueCrashItems,
      uniqueCrashKey,
      uniqueCrashLastAnalysisAt,
      uniqueCrashTotalCount,
      closeCreateModal,
      closeUniqueCrashFilter,
      cancelCrashDeleteSelection,
      setCrashFixSelected,
      setUniqueCrashSelected,
      setUniqueCrashFilterAll,
      setUniqueCrashFilterValue,
      cancelCrashFixSelection,
      canSelectCrashFix,
      canSelectUniqueCrash,
      uniqueCrashSelectionDisabledReason,
      uniqueCrashSelectionMode,
      toggleCrashDeleteMode,
      toggleCrashFixMode,
      toggleUniqueCrashFilter,
      togglePathPicker
    };
    return controller;
}
