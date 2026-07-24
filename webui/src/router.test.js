import { describe, expect, it } from 'vitest';
import router from './router';

describe('router', () => {
  it('resolves task tabs and report query state', () => {
    const route = router.resolve('/tasks/run-1/crashes?report=2&driver=9&file=crash-abc');
    expect(route.name).toBe('task-detail');
    expect(route.params.taskId).toBe('run-1');
    expect(route.params.tab).toBe('crashes');
    expect(route.query.report).toBe('2');
  });

  it('resolves a child driver coverage page', () => {
    const route = router.resolve('/tasks/run-1/coverage/drivers/1/versions/4');

    expect(route.name).toBe('driver-coverage');
    expect(route.params.taskId).toBe('run-1');
    expect(route.params.driverId).toBe('1');
    expect(route.params.seq).toBe('4');
  });

  it('keeps the legacy child driver coverage route as latest-version fallback', () => {
    const route = router.resolve('/tasks/run-1/coverage/drivers/1');

    expect(route.name).toBe('driver-coverage-latest');
    expect(route.params.taskId).toBe('run-1');
    expect(route.params.driverId).toBe('1');
  });
});
