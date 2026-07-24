import { mount } from '@vue/test-utils';
import { describe, expect, it, vi } from 'vitest';
import { reactive } from 'vue';
import { autofuzzKey } from '../appContext';
import DashboardView from './DashboardView.vue';

describe('DashboardView', () => {
  it('shows the four primary KPIs without a duplicate recent task panel', () => {
    const ui = reactive({
      messages: {dashboard: ''},
      taskCounts: {total: 7},
      totalTaskNote: 'registry 中的任务',
      runningTasks: 1,
      discoveredIssues: 30,
      issueNote: '库问题 2 · driver 问题 0',
      queueTotal: 3,
      queueNote: '运行 1 · 排队 2',
      statusColumns: [
        {label: '运行中', tasks: [{id: 'run-1', name: 'libexif', status: 'running', current_stage: 'fuzzing'}]},
        {label: '待启动', tasks: []},
        {label: '已完成', tasks: []},
        {label: '需关注', tasks: []}
      ],
      recentIssues: [],
      navigate: vi.fn(),
      openTask: vi.fn(),
      openIssue: vi.fn(),
      statusLabel: value => value,
      issueKey: issue => issue.file,
      issueDriverLabel: () => 'd1/v1',
      crashBadge: () => ({className: 'pending', label: '未分析'})
    });

    const wrapper = mount(DashboardView, {
      global: {provide: {[autofuzzKey]: ui}}
    });

    expect(wrapper.findAll('.kpi-card')).toHaveLength(4);
    expect(wrapper.text()).not.toContain('最近 Task');
    expect(wrapper.text()).toContain('发现问题');
  });
});
