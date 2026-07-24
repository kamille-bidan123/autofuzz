import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import { reactive } from 'vue';
import { autofuzzKey } from '../../appContext';
import OverviewTab from './OverviewTab.vue';

describe('OverviewTab', () => {
  it('renders all six setup stages plus fuzz and LLM analysis', () => {
    const ui = reactive({
      linearStages: Array.from({length: 6}, (_, index) => ({
        id: `stage-${index + 1}`,
        index: index + 1,
        name: `阶段 ${index + 1}`,
        owner: 'Go',
        status: index === 0 ? 'completed' : 'pending'
      })),
      fuzzStage: {name: '持续 Fuzz 测试', owner: 'libFuzzer', status: 'running', detail: 'driver 1'},
      analysisStage: {name: 'LLM 优化分析', owner: 'Codex CLI', status: 'pending', detail: '等待', result: ''},
      flowForwardActive: false,
      flowBackActive: false,
      flowRows: [],
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

    expect(wrapper.findAll('.linear-stage')).toHaveLength(6);
    expect(wrapper.findAll('.stage')).toHaveLength(8);
    expect(wrapper.text()).toContain('持续 Fuzz 测试');
    expect(wrapper.text()).toContain('LLM 优化分析');
    expect(wrapper.findAll('.driver-schedule-tile')).toHaveLength(3);
    expect(wrapper.find('.driver-schedule-tile.running').text()).toContain('d1');
    expect(wrapper.find('.driver-schedule-tile.next').text()).toContain('v2');
    expect(wrapper.find('.driver-schedule-tile.idle').text()).toContain('d3');
  });
});
