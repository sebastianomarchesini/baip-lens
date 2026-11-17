import type { AppUsage } from '@baip-lens/model';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { appColumns } from '../pages/Apps';
import { UsageStatus } from './UsageStatus';

const objectStatus = (container: HTMLElement) =>
  container.querySelector('[data-component-name="ObjectStatus"]');

describe('UsageStatus', () => {
  it('shows an unused app with the semantics of its finding, on two lines and as tooltip', () => {
    const usage: AppUsage = { state: 'idle', signal: 'no_route', confidence: 'high' };
    const { container } = render(<UsageStatus usage={usage} />);
    expect(screen.getByText('Looks unused')).toBeInTheDocument();
    expect(screen.getByText('No route (high)')).toBeInTheDocument();
    expect(container.querySelector('.usage-cell')?.getAttribute('title')).toBe(
      'Looks unused: no route, high confidence',
    );
    expect(objectStatus(container)?.getAttribute('data-state')).toBe('Information');
    expect(
      container.querySelector('[data-component-name="ObjectStatusDefaultIcon"]'),
    ).not.toBeNull();
  });

  it('gives unknown its own icon, so it never looks like "no finding"', () => {
    const { container } = render(
      <UsageStatus usage={{ state: 'unknown', reason: 'traffic_not_checked' }} />,
    );
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText('Traffic not checked')).toBeInTheDocument();
    expect(objectStatus(container)?.getAttribute('data-state')).toBe('None');
    // React 19 passes `name` to the custom element as a property, not always as an attribute.
    const icon = container.querySelector<HTMLElement & { name?: string }>(
      '[data-component-name="ObjectStatusIconContainer"] > *',
    );
    expect(icon?.getAttribute('name') ?? icon?.name).toBe('question-mark');
    expect(container.querySelector('[data-component-name="ObjectStatusDefaultIcon"]')).toBeNull();
  });

  it('shows an app in use as Positive, with its last request', () => {
    const { container } = render(
      <UsageStatus usage={{ state: 'active', lastRequestAt: '2026-09-28T23:50:00.000Z' }} />,
    );
    expect(screen.getByText('In use')).toBeInTheDocument();
    expect(screen.getByText(/^Last request Sep 28, 2026/)).toBeInTheDocument();
    expect(objectStatus(container)?.getAttribute('data-state')).toBe('Positive');
  });

  it('shows "not judged" as plain secondary text with its reason', () => {
    const { container } = render(
      <UsageStatus usage={{ state: 'not_assessed', reason: 'stopped' }} />,
    );
    expect(objectStatus(container)).toBeNull();
    expect(container.querySelector('.usage-not-judged')?.textContent).toBe('Not judged');
    expect(screen.getByText('Stopped')).toBeInTheDocument();
  });

  it('shows a dash when there is no verdict', () => {
    for (const usage of [null, undefined]) {
      const { container, unmount } = render(<UsageStatus usage={usage} />);
      expect(objectStatus(container)).toBeNull();
      expect(container.textContent).toBe('—');
      unmount();
    }
  });
});

describe('appColumns', () => {
  const ids = (projects: boolean) =>
    appColumns(projects).map((c) => c.id ?? (typeof c.accessor === 'string' ? c.accessor : ''));

  it('has a Usage column for a Cloud Foundry scan, right after the findings count', () => {
    const cf = ids(false);
    expect(cf.indexOf('usage')).toBe(cf.indexOf('findings') + 1);
    const usage = appColumns(false).find((c) => c.id === 'usage');
    // Pops in under the app name on narrow screens and is never a grouping key.
    expect(usage).toMatchObject({ responsivePopIn: true, disableGroupBy: true });
  });

  it('has no Usage column for projects, which APP_IDLE never judges', () => {
    expect(ids(true)).not.toContain('usage');
  });
});
