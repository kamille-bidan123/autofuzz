import { describe, expect, it } from 'vitest';
import { buildDriverSchedule } from './useAutofuzz';

describe('buildDriverSchedule', () => {
  it('marks running drivers green before next-batch drivers and leaves others idle', () => {
    const now = Date.parse('2026-07-24T09:00:00+08:00');
    const schedule = buildDriverSchedule({
      mode: 'multi',
      iteration: 3,
      max_parallel_targets: 1,
      running_targets: [1],
      queued_targets: [2, 3],
      next_targets: [1, 2],
      next_analysis_at: '2026-07-24T09:01:05+08:00'
    }, [
      {driver_id: 3, seq: 1, status: 'queued'},
      {driver_id: 1, seq: 4, status: 'running'},
      {driver_id: 2, seq: 2, status: 'queued'}
    ], now);

    expect(schedule.items.map(item => [item.driverId, item.seq, item.state])).toEqual([
      [1, 4, 'running'],
      [2, 2, 'next'],
      [3, 1, 'idle']
    ]);
    expect(schedule.countdown).toBe('下一轮 01:05');
  });

  it('is unavailable for a single-driver coverage snapshot', () => {
    expect(buildDriverSchedule({mode: 'single'}, [])).toBeNull();
  });

  it('matches running and next states by driver version when version queues are present', () => {
    const schedule = buildDriverSchedule({
      mode: 'multi',
      running_versions: [{driver_id: 1, seq: 1}],
      queued_versions: [{driver_id: 1, seq: 2}],
      next_versions: [{driver_id: 1, seq: 2}]
    }, [
      {driver_id: 1, seq: 2, status: 'queued'},
      {driver_id: 1, seq: 1, status: 'queued'}
    ]);

    expect(schedule.items.map(item => [item.driverId, item.seq, item.state])).toEqual([
      [1, 1, 'running'],
      [1, 2, 'next']
    ]);
  });

  it('uses elapsed client time instead of comparing server and client clocks', () => {
    const receivedAt = Date.parse('2026-07-24T17:00:00+08:00');
    const schedule = buildDriverSchedule({
      mode: 'multi',
      timestamp: '2026-07-24T09:00:00+08:00',
      next_analysis_at: '2026-07-24T09:10:00+08:00',
      analysis_remaining_seconds: 600
    }, [
      {driver_id: 1, seq: 1, status: 'running'}
    ], receivedAt + 60_000, receivedAt);

    expect(schedule.countdown).toBe('下一轮 09:00');
  });

  it('shows an imminent state instead of a permanent zero countdown', () => {
    const receivedAt = Date.parse('2026-07-24T09:00:00+08:00');
    const schedule = buildDriverSchedule({
      mode: 'multi',
      analysis_remaining_seconds: 5,
      next_analysis_at: '2026-07-24T09:00:05+08:00'
    }, [], receivedAt + 10_000, receivedAt);

    expect(schedule.countdown).toBe('下一轮 即将调度');
  });
});
