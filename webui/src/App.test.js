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
});
