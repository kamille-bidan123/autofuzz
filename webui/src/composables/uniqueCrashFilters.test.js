import { describe, expect, it } from 'vitest';
import {
  buildUniqueCrashFilterOptions,
  crashFilenameKind,
  filterUniqueCrashItems
} from './useAutofuzz';

const crashes = [
  {entry: {file: 'leak-aaa', type: 'leak', report_status: 'pending'}},
  {entry: {file: 'crash-bbb', type: 'heap-buffer-overflow', report_status: 'completed', classification: 'library_bug'}},
  {entry: {file: 'timeout-ccc', type: 'timeout', report_status: 'skipped'}}
];

describe('unique crash filters', () => {
  it('derives crash filter values from file names', () => {
    expect(crashFilenameKind('leak-378c1')).toBe('leak');
    expect(crashFilenameKind('crash-002c')).toBe('crash');
    expect(crashFilenameKind('slow-unit-001')).toBe('slow-unit');
  });

  it('builds filter options with counts', () => {
    expect(buildUniqueCrashFilterOptions(crashes, 'crash').map(option => [option.value, option.count])).toEqual([
      ['crash', 1],
      ['leak', 1],
      ['timeout', 1]
    ]);
    expect(buildUniqueCrashFilterOptions(crashes, 'type').map(option => option.value)).toEqual([
      'heap-buffer-overflow',
      'leak',
      'timeout'
    ]);
  });

  it('filters by file-name kind, displayed status, and type', () => {
    expect(filterUniqueCrashItems(crashes, {})).toHaveLength(3);
    expect(filterUniqueCrashItems(crashes, {crash: new Set(['leak'])}).map(item => item.entry.file)).toEqual(['leak-aaa']);
    expect(filterUniqueCrashItems(crashes, {status: new Set(['library_bug:库问题'])}).map(item => item.entry.file)).toEqual(['crash-bbb']);
    expect(filterUniqueCrashItems(crashes, {type: new Set(['timeout'])}).map(item => item.entry.file)).toEqual(['timeout-ccc']);
  });

  it('supports clearing all selections for a column', () => {
    expect(filterUniqueCrashItems(crashes, {crash: new Set()})).toEqual([]);
  });
});
