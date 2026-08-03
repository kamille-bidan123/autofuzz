import { mount } from '@vue/test-utils';
import { describe, expect, it, vi } from 'vitest';
import { reactive } from 'vue';
import { autofuzzKey } from '../../appContext';
import OverviewTab from './OverviewTab.vue';

describe('OverviewTab', () => {
  it('renders all six setup stages plus fuzz and LLM analysis', () => {
    const ui = reactive({
      linearStages: Array.from({length: 6}, (_, index) => ({
        id: index === 2 ? 'configured' : `stage-${index + 1}`,
        index: index + 1,
        name: `阶段 ${index + 1}`,
        owner: 'Go',
        status: index === 0 ? 'completed' : 'pending'
      })),
      fuzzStage: {name: '持续 Fuzz 测试', owner: 'libFuzzer', status: 'running', detail: 'driver 1'},
      analysisStage: {name: 'LLM 优化分析', owner: 'Codex CLI', status: 'pending', detail: '等待', result: ''},
      taskControlSummaryItems: [
        {label: '状态', value: '运行中', className: 'running'},
        {label: '当前阶段', value: '持续 Fuzz 测试', className: 'running'},
        {label: 'Loop', value: '等待下一轮分析', className: 'running'}
      ],
      controlLoopSummary: {
        phase: '等待下一轮分析',
        stage: '持续 Fuzz 测试',
        statusClass: 'running',
        drivers: 'd1/v4',
        driverOverflow: 0,
        countdown: '下一轮 01:05',
        latest: '尚无优化记录',
        result: '等待下一轮分析'
      },
      coverageDriverMeta: '运行 1/3 · queued 2',
      coverageLoading: false,
      driverBoardRows: [
        {
          key: '1:4',
          driverId: 1,
          seq: 4,
          label: 'd1/v4',
          status: '运行中',
          className: 'running',
          seeds: 7,
          executed: 5,
          partial: 1,
          uncovered: 2,
          apiCount: 3,
          crashCount: 1,
          hasDetails: true
        }
      ],
      coverageGapSummary: {
        apiMeta: '3/5 · 60%',
        executed: 5,
        full: 4,
        partial: 1,
        uncoveredBranches: 2,
        missingCount: 2,
        missingApis: [{name: 'missing_api', header: '/src/sample.h', headerName: 'sample.h'}],
        topDrivers: [{key: '1:4', driver_id: 1, seq: 4, apis: [{name: 'api_a'}]}]
      },
      crashWorkbenchSummary: {
        total: 1,
        pending: 0,
        queued: 0,
        running: 0,
        completed: 1,
        classified: 1,
        fixable: 1,
        queueRunning: 0,
        queuePending: 0,
        recent: []
      },
      flowForwardActive: false,
      flowBackActive: false,
      flowRows: [],
      apiDriverTitle: driver => `d${driver.driver_id} / v${driver.seq}`,
      setDetailTab: () => {},
      canOpenLibraryConfig: true,
      openLibraryConfig: vi.fn(),
      openDriverCoverage: () => {},
      driverSchedule: {
        meta: '轮次 3 · 运行 1/3 · 等待 2 · 并发 1',
        countdown: '下一轮 01:05',
        items: [
          {driverId: 1, seq: 4, state: 'running', ariaLabel: 'd1 running'},
          {driverId: 2, seq: 2, state: 'next', ariaLabel: 'd2 next'},
          {driverId: 3, seq: 1, state: 'idle', ariaLabel: 'd3 idle'}
        ]
      },
      detail: {meta: 'Task test'}
    });

    const wrapper = mount(OverviewTab, {
      global: {provide: {[autofuzzKey]: ui}}
    });

    expect(wrapper.find('.overview-control').element.firstElementChild?.classList.contains('overview-stage-panel')).toBe(true);
    expect(wrapper.findAll('.linear-stage')).toHaveLength(6);
    expect(wrapper.findAll('.stage')).toHaveLength(8);
    expect(wrapper.text()).toContain('当前 Loop');
    expect(wrapper.text()).toContain('Driver 状态');
    expect(wrapper.findAll('.driver-board-tile')).toHaveLength(1);
    expect(wrapper.text()).toContain('持续 Fuzz 测试');
    expect(wrapper.text()).toContain('LLM 优化分析');
    expect(wrapper.text()).not.toContain('Codex CLI');
    expect(wrapper.text()).not.toContain('libFuzzer');
    expect(wrapper.text()).not.toContain('Go');
    expect(wrapper.findAll('.driver-schedule-tile')).toHaveLength(3);
    expect(wrapper.find('.driver-schedule-tile.running').text()).toContain('d1');
    expect(wrapper.find('.driver-schedule-tile.next').text()).toContain('v2');
    expect(wrapper.find('.driver-schedule-tile.idle').text()).toContain('d3');
    expect(wrapper.find('.stage-action-button').text()).toBe('查看配置');
  });
});
