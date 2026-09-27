import { describe, expect, it } from 'vitest';
import { severityColor, severityOf } from './components';

describe('severityOf', () => {
  it('maps fraud-score bands to severities', () => {
    expect(severityOf(95)).toBe('critical');
    expect(severityOf(90)).toBe('critical');
    expect(severityOf(89)).toBe('high');
    expect(severityOf(75)).toBe('high');
    expect(severityOf(74)).toBe('medium');
    expect(severityOf(50)).toBe('medium');
    expect(severityOf(49)).toBe('low');
    expect(severityOf(0)).toBe('low');
  });

  it('never falls through to green for unknown values', () => {
    expect(severityOf(NaN)).toBe('unknown');
    expect(severityOf(-1)).toBe('unknown');
    expect(severityColor('unknown')).toBe('var(--muted)');
    expect(severityColor('mystery')).toBe('var(--muted)');
  });
});

describe('severityColor', () => {
  it('returns distinct theme tokens per severity (risk hues only)', () => {
    const colors = new Set(['critical', 'high', 'medium', 'low'].map(severityColor));
    expect(colors.size).toBe(4);
    expect(severityColor('critical')).toBe('var(--critical)');
    expect(severityColor('low')).toBe('var(--low)');
  });
});
