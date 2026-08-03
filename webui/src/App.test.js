import { mount, flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.vue';
import router from './router';

function jsonResponse(data, ok = true) {
  return Promise.resolve({
    ok,
    status: ok ? 200 : 500,
    json: () => Promise.resolve(data)
  });
}

describe('App routing', () => {
  let wrapper;

  beforeEach(async () => {
    vi.stubGlobal('fetch', vi.fn(url => {
      const path = String(url);
      if (path === '/api/runs') return jsonResponse([]);
      if (path === '/api/overview') {
        return jsonResponse({
          tasks: {total: 0},
          issues: {},
          crash_queue: {},
          recent_tasks: [],
          recent_issues: []
        });
      }
      if (path === '/api/coverage-queue') {
        return jsonResponse({
          generated_at: '2026-08-01T09:00:00+08:00',
          summary: {
            total: 2,
            queued: 1,
            running: 1,
            refresh: 1,
            required: 1,
            snapshots: 1,
            branch_reach: 1
          },
          items: [
            {
              id: 'llvm-cov-000001',
              status: 'running',
              mode: 'required',
              mode_label: '前台等待',
              kind: 'branch_reach',
              kind_label: 'Proof 分支触达校验',
              task_id: 'run-1',
              task_name: 'libexif',
              repository_url: '/src/libexif',
              current_stage: 'fuzzing',
              driver_id: 1,
              seq: 2,
              snapshot_dir: '/work/libexif/logs/fuzzing/driver-targets/driver-0001/v002',
              profdata_path: '/work/libexif/logs/fuzzing/driver-targets/driver-0001/v002/validate/seed-1.profdata',
              binary_path: '/work/libexif/logs/fuzzing/driver-targets/driver-0001/v002/cov_driver',
              queued_at: '2026-08-01T08:59:00+08:00',
              started_at: '2026-08-01T08:59:10+08:00',
              coalesced: 1
            },
            {
              id: 'llvm-cov-000002',
              status: 'queued',
              position: 1,
              mode: 'refresh',
              mode_label: '后台刷新',
              kind: 'live_refresh',
              kind_label: '实时覆盖刷新',
              task_id: 'run-2',
              task_name: 'freetype',
              repository_url: '/src/freetype',
              current_stage: 'fuzzing',
              driver_id: 18,
              seq: 3,
              snapshot_dir: '/work/freetype/logs/fuzzing/driver-targets/driver-0018/v003',
              profdata_path: '/work/freetype/logs/fuzzing/driver-targets/driver-0018/v003/monitor/aggregate.profdata',
              binary_path: '/work/freetype/logs/fuzzing/driver-targets/driver-0018/v003/cov_driver',
              queued_at: '2026-08-01T08:59:20+08:00',
              coalesced: 4
            }
          ]
        });
      }
      if (path === '/api/defaults') {
        return jsonResponse({
          jobs: 1,
          pool_size: 1,
          max_fuzz_drivers: 1,
          stop_after: 'fuzzing',
          codex_command: 'codex'
        });
      }
      if (path === '/api/runs/run-1') {
        return jsonResponse({
          id: 'run-1',
          status: 'pending',
          request: {repository_url: '/src/libexif'},
          stages: [{id: 'cloned', status: 'completed'}],
          target_dir: '/work/libexif'
        });
      }
      if (path.startsWith('/api/runs/run-1/fuzz-flow')) return jsonResponse({history: [], current: null});
      if (path === '/api/runs/run-1/coverage') {
        return jsonResponse({
          mode: 'multi',
          available: true,
          timestamp: '2026-07-24T09:00:00+08:00',
          api_coverage: {
            available: true,
            total_apis: 2,
            covered_apis: 1,
            coverage: 0.5,
            driver_count: 1,
            apis: [
              {name: 'sample_context_create', header: '/src/sample.h', covered: true, drivers: [{driver_id: 1, seq: 2}]},
              {name: 'sample_context_destroy', header: '/src/sample.h', covered: false, drivers: []}
            ]
          },
          targets: [{
            driver_id: 1,
            status: 'running',
            seq: 2,
            seed_count: 3,
            uncovered_count: 0,
            summary: {executed_functions: 1, full_functions: 1, partial_functions: 0},
            coverage: {
              full: [{file: 'sample.c', function: 'parse', start_line: 10, end_line: 12, entry_count: 4}],
              partial: []
            }
          }]
        });
      }
      if (path === '/api/runs/run-1/coverage/function-sources?driver_id=1&seq=2') {
        return jsonResponse({
          available: true,
          driver_id: 1,
          seq: 2,
          functions: [{
            file: 'sample.c',
            function: 'parse',
            start_line: 10,
            end_line: 12,
            coverage: 'full',
            source: 'int parse(void) {\\n  return 0;\\n}'
          }]
        });
      }
      return jsonResponse({error: `unexpected request: ${path}`}, false);
    }));
    await router.push('/dashboard');
    await router.isReady();
  });

  afterEach(() => {
    wrapper?.unmount();
    vi.unstubAllGlobals();
  });

  it('keeps the selected task and tab in the route', async () => {
    wrapper = mount(App, {global: {plugins: [router]}});
    await flushPromises();
    expect(wrapper.text()).toContain('运行看板');

    await router.push('/tasks/run-1/overview');
    await flushPromises();
    await flushPromises();

    expect(router.currentRoute.value.params.taskId).toBe('run-1');
    expect(wrapper.text()).toContain('libexif');
    expect(wrapper.findAll('.linear-stage')).toHaveLength(6);
  });

  it('renders the global coverage queue page from the sidebar route', async () => {
    wrapper = mount(App, {global: {plugins: [router]}});
    await flushPromises();

    await router.push('/coverage-queue');
    await flushPromises();
    await flushPromises();

    expect(router.currentRoute.value.name).toBe('coverage-queue');
    expect(wrapper.text()).toContain('覆盖队列');
    expect(wrapper.text()).toContain('当前执行');
    expect(wrapper.text()).toContain('等待队列');
    expect(wrapper.text()).toContain('Proof 分支触达校验');
    expect(wrapper.text()).toContain('实时覆盖刷新');
    expect(wrapper.text()).toContain('d18/v3');
  });

  it('opens child driver coverage as a routed page instead of a modal', async () => {
    const defaultFetch = fetch.getMockImplementation();
    let releaseCoverage;
    fetch.mockImplementation(url => {
      if (String(url) !== '/api/runs/run-1/coverage') return defaultFetch(url);
      return new Promise(resolve => {
        releaseCoverage = () => defaultFetch(url).then(resolve);
      });
    });

    wrapper = mount(App, {global: {plugins: [router]}});
    await flushPromises();

    await router.push('/tasks/run-1/coverage/drivers/1/versions/2');
    await flushPromises();

    expect(router.currentRoute.value.name).toBe('driver-coverage');
    expect(wrapper.find('.driver-coverage-page').exists()).toBe(true);
    expect(wrapper.find('.driver-coverage-page .modal').exists()).toBe(false);
    expect(wrapper.text()).toContain('子 driver d1/v2 覆盖详情');
    expect(wrapper.text()).toContain('正在加载子 driver 覆盖详情');
    expect(releaseCoverage).toBeTypeOf('function');
    expect(fetch).toHaveBeenCalledWith('/api/runs/run-1/coverage/function-sources?driver_id=1&seq=2');

    releaseCoverage();
    await flushPromises();
    await flushPromises();

    await wrapper.find('.driver-coverage-page .back-button').trigger('click');
    await flushPromises();

    expect(router.currentRoute.value.fullPath).toBe('/tasks/run-1/coverage');
  });

  it('renders the overview driver schedule before coverage data finishes loading', async () => {
    const defaultFetch = fetch.getMockImplementation();
    let releaseCoverage;
    fetch.mockImplementation(url => {
      if (String(url) === '/api/runs/run-1') {
        return jsonResponse({
          id: 'run-1',
          status: 'running',
          request: {repository_url: '/src/libexif'},
          stages: [{id: 'cloned', status: 'completed'}, {id: 'fuzzing', status: 'running'}],
          target_dir: '/work/libexif',
          driver_schedule: {
            mode: 'multi',
            timestamp: '2026-08-01T09:00:00+08:00',
            iteration: 3,
            active_targets: 1,
            max_parallel_targets: 1,
            running_versions: [{driver_id: 1, seq: 2}],
            queued_versions: [{driver_id: 2, seq: 1}],
            next_versions: [{driver_id: 2, seq: 1}],
            analysis_remaining_seconds: 120,
            targets: [
              {driver_id: 1, seq: 2, status: 'running'},
              {driver_id: 2, seq: 1, status: 'queued'}
            ]
          }
        });
      }
      if (String(url) !== '/api/runs/run-1/coverage') return defaultFetch(url);
      return new Promise(resolve => {
        releaseCoverage = () => defaultFetch(url).then(resolve);
      });
    });

    wrapper = mount(App, {global: {plugins: [router]}});
    await flushPromises();

    await router.push('/tasks/run-1/overview');
    await flushPromises();
    await flushPromises();

    expect(wrapper.text()).toContain('子 driver 调度');
    expect(wrapper.findAll('.driver-schedule-tile')).toHaveLength(2);
    expect(wrapper.find('.driver-schedule-tile.running').text()).toContain('d1');
    expect(wrapper.find('.driver-schedule-tile.next').text()).toContain('d2');

    if (releaseCoverage) {
      releaseCoverage();
      await flushPromises();
      await flushPromises();
    }
  });

  it('renders the task overview control center with coverage-derived driver data', async () => {
    const defaultFetch = fetch.getMockImplementation();
    fetch.mockImplementation(url => {
      if (String(url) !== '/api/runs/run-1') return defaultFetch(url);
      return jsonResponse({
        id: 'run-1',
        status: 'completed',
        request: {repository_url: '/src/libexif'},
        stages: [{id: 'cloned', status: 'completed'}, {id: 'fuzzing', status: 'completed'}],
        target_dir: '/work/libexif'
      });
    });

    wrapper = mount(App, {global: {plugins: [router]}});
    await flushPromises();

    await router.push('/tasks/run-1/overview');
    await flushPromises();
    await flushPromises();

    expect(wrapper.text()).toContain('当前 Loop');
    expect(wrapper.text()).toContain('Driver 状态');
    expect(wrapper.text()).toContain('覆盖缺口');
    expect(wrapper.text()).toContain('Crash 工作台');
    expect(wrapper.find('.driver-board-tile').text()).toContain('d1/v2');
    expect(wrapper.find('.driver-board-tile').text()).toContain('3 seeds');
  });

  it('renders exported API coverage with driver icons', async () => {
    const defaultFetch = fetch.getMockImplementation();
    fetch.mockImplementation(url => {
      if (String(url) !== '/api/runs/run-1') return defaultFetch(url);
      return jsonResponse({
        id: 'run-1',
        status: 'completed',
        request: {repository_url: '/src/libexif'},
        stages: [{id: 'cloned', status: 'completed'}],
        target_dir: '/work/libexif'
      });
    });

    wrapper = mount(App, {global: {plugins: [router]}});
    await flushPromises();

    await router.push('/tasks/run-1/coverage');
    await flushPromises();
    await flushPromises();

    expect(wrapper.text()).toContain('导出 API 覆盖');
    expect(wrapper.text()).toContain('1/2 · 50%');
    expect(wrapper.text()).toContain('sample_context_create');
    expect(wrapper.text()).toContain('sample_context_destroy');
    expect(wrapper.find('.api-driver-icon').text()).toBe('d1');

    const toggleButtons = wrapper.findAll('.api-coverage-toggle button');
    expect(toggleButtons.map(button => button.text())).toEqual(['按 API', '按 Driver']);
    await toggleButtons[1].trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain('d1 / v2');
    expect(wrapper.text()).toContain('1 个 API · 运行中');
    expect(wrapper.find('.driver-api-chip strong').text()).toBe('sample_context_create');
    expect(wrapper.text()).not.toContain('sample_context_destroy');
  });

  it('shows a loading state while coverage data is being fetched', async () => {
    const defaultFetch = fetch.getMockImplementation();
    let releaseCoverage;
    fetch.mockImplementation(url => {
      const path = String(url);
      if (path === '/api/runs/run-1') {
        return jsonResponse({
          id: 'run-1',
          status: 'completed',
          request: {repository_url: '/src/libexif'},
          stages: [{id: 'cloned', status: 'completed'}],
          target_dir: '/work/libexif'
        });
      }
      if (path !== '/api/runs/run-1/coverage') return defaultFetch(url);
      return new Promise(resolve => {
        releaseCoverage = () => defaultFetch(url).then(resolve);
      });
    });

    wrapper = mount(App, {global: {plugins: [router]}});
    await flushPromises();

    await router.push('/tasks/run-1/coverage');
    await flushPromises();

    expect(wrapper.text()).toContain('正在加载覆盖数据...');
    expect(wrapper.text()).toContain('正在加载 API 覆盖数据...');
    expect(wrapper.text()).not.toContain('覆盖数据将在 fuzzing 阶段开始后可用');

    releaseCoverage();
    await flushPromises();
  });
});
