import { describe, expect, it } from 'vitest';
import { buildCrashReportCards } from './useAutofuzz';

const reports = [
  {
    entry: {file: 'crash-a', report_status: 'completed'},
    report: {analysis: 'root cause A'}
  },
  {
    entry: {file: 'crash-b', report_status: 'completed'},
    report: {analysis: 'root cause B'}
  }
];

describe('buildCrashReportCards', () => {
  it('returns only the selected crash when a file is specified', () => {
    const cards = buildCrashReportCards(reports, 'crash-b');

    expect(cards).toHaveLength(1);
    expect(cards[0].file).toBe('crash-b');
    expect(cards[0].focused).toBe(true);
  });

  it('keeps the snapshot report view aggregated without a file filter', () => {
    expect(buildCrashReportCards(reports)).toHaveLength(2);
  });

  it('does not fall back to unrelated reports when the selected crash is missing', () => {
    expect(buildCrashReportCards(reports, 'crash-missing')).toEqual([]);
  });
});
