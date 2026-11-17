import type { AppInventoryItem, AppUsage } from '@baip-lens/model';
import { describe, expect, it } from 'vitest';
import { formatDate, formatDateTime } from './format';
import { idleHint, usageRank, usageView } from './usage';

const item = (usage: AppUsage | null): AppInventoryItem =>
  ({ usage }) as unknown as AppInventoryItem;

describe('usageView', () => {
  it('names the signal and its confidence for an app that looks unused', () => {
    expect(usageView({ state: 'idle', signal: 'no_route', confidence: 'high' })).toEqual({
      kind: 'idle',
      label: 'Looks unused',
      detail: 'No route (high)',
      text: 'Looks unused: no route, high confidence',
    });
  });

  it('says why an app is unknown, so it never reads as "no finding"', () => {
    expect(usageView({ state: 'unknown', reason: 'traffic_not_measurable' })).toEqual({
      kind: 'unknown',
      label: 'Unknown',
      detail: 'No measurable route',
      text: 'Unknown: no measurable route',
    });
    expect(usageView({ state: 'unknown', reason: 'data_unavailable' }).text).toBe(
      'Unknown: routes or processes not readable',
    );
  });

  it('says why traffic could not tell: too little history, Log Cache not readable, or turned off', () => {
    const text = (reason: 'window_too_short' | 'traffic_unreadable' | 'traffic_check_off') =>
      usageView({ state: 'unknown', reason });
    expect(text('window_too_short')).toMatchObject({
      kind: 'unknown',
      detail: 'Log history too short',
      text: 'Unknown: log history too short',
    });
    expect(text('traffic_unreadable').text).toBe('Unknown: Log Cache not readable');
    expect(text('traffic_check_off').text).toBe('Unknown: traffic check turned off');
  });

  it('names the signal of a silent app and its confidence', () => {
    const silent = usageView({ state: 'idle', signal: 'no_traffic', confidence: 'medium' });
    expect([silent.detail, silent.text]).toEqual([
      'No traffic (medium)',
      'Looks unused: no request in the router logs, medium confidence',
    ]);
    const stopped = usageView({ state: 'idle', signal: 'stopped', confidence: 'high' });
    expect([stopped.detail, stopped.text]).toEqual([
      'Stopped 90+ days (high)',
      'Looks unused: stopped for more than 90 days, high confidence',
    ]);
  });

  it('shows an app in use with its last request', () => {
    const at = '2026-09-28T23:50:00.000Z';
    expect(usageView({ state: 'active', lastRequestAt: at })).toEqual({
      kind: 'active',
      label: 'In use',
      detail: `Last request ${formatDate(at)}`,
      text: `In use: last request ${formatDateTime(at)}`,
    });
  });

  it('says why an app is not judged at all', () => {
    expect(usageView({ state: 'not_assessed', reason: 'worker_health_check' })).toEqual({
      kind: 'not_assessed',
      label: 'Not judged',
      detail: 'Worker, process health check',
      text: 'Not judged: worker, process health check',
    });
  });

  it('shows a dash when the rule did not run, also for reports written before it existed', () => {
    const none = { kind: 'none', label: '—', detail: '', text: '—' };
    expect(usageView(null)).toEqual(none);
    expect(usageView(undefined)).toEqual(none);
  });
});

describe('usageRank', () => {
  it('sorts unused first, then unknown, in use, not judged and no data', () => {
    const ranked = [
      null,
      { state: 'not_assessed', reason: 'stopped' },
      { state: 'active', lastRequestAt: '2026-09-28T23:50:00.000Z' },
      { state: 'idle', signal: 'no_route', confidence: 'high' },
      { state: 'unknown', reason: 'traffic_not_checked' },
    ] as const satisfies readonly (AppUsage | null)[];
    expect([...ranked].sort((a, b) => usageRank(b) - usageRank(a)).map((u) => u?.state)).toEqual([
      'idle',
      'unknown',
      'active',
      'not_assessed',
      undefined,
    ]);
  });
});

describe('idleHint', () => {
  it('lists each signal with its confidence, then the unknown apps', () => {
    const apps = [
      item({ state: 'idle', signal: 'no_route', confidence: 'high' }),
      item({ state: 'idle', signal: 'no_traffic', confidence: 'medium' }),
      item({ state: 'idle', signal: 'no_route', confidence: 'high' }),
      item({ state: 'unknown', reason: 'window_too_short' }),
      item({ state: 'active', lastRequestAt: '2026-09-28T23:50:00.000Z' }),
      item({ state: 'not_assessed', reason: 'stopped' }),
      item(null),
    ];
    expect(idleHint(apps)).toBe('2 no route (high) · 1 no traffic (medium) · 1 unknown');
  });

  it('says so when no app looks unused and nothing is unknown', () => {
    expect(idleHint([item({ state: 'not_assessed', reason: 'stopped' })])).toBe(
      'no app looks unused',
    );
  });
});
