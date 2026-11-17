import type {
  AppInventoryItem,
  AppUsage,
  Confidence,
  UsageNotAssessedReason,
  UsageSignal,
  UsageUnknownReason,
} from '@baip-lens/model';
import { formatDate, formatDateTime } from './format';

/** Short enough for the second line of a 160 px table cell and for the KPI hint. */
const SIGNAL_SHORT: Record<UsageSignal, string> = {
  no_route: 'no route',
  no_traffic: 'no traffic',
  stopped: 'stopped 90+ days',
};

/** The same signals in full, for the tooltip. */
const SIGNAL_TEXT: Record<UsageSignal, string> = {
  no_route: 'no route',
  no_traffic: 'no request in the router logs',
  stopped: 'stopped for more than 90 days',
};

const CONFIDENCE_TEXT: Record<Confidence, string> = {
  high: 'high confidence',
  medium: 'medium confidence',
  low: 'low confidence',
};

const REASON_TEXT: Record<UsageUnknownReason | UsageNotAssessedReason, string> = {
  traffic_not_checked: 'traffic not checked',
  traffic_check_off: 'traffic check turned off',
  traffic_unreadable: 'Log Cache not readable',
  window_too_short: 'log history too short',
  // TCP, internal-domain or unclassified routes only: none leaves a router log (D6).
  traffic_not_measurable: 'no measurable route',
  data_unavailable: 'routes or processes not readable',
  stopped: 'stopped',
  no_web_instance: 'worker, no web instance',
  worker_health_check: 'worker, process health check',
};

export type UsageKind = AppUsage['state'] | 'none';

export interface UsageView {
  kind: UsageKind;
  /** The status itself, short enough for a table cell: "Looks unused", "Unknown", "In use". */
  label: string;
  /** Why: the signal and its confidence, the reason, or the last request. */
  detail: string;
  /** Label and detail as one sentence: the tooltip, the sort and filter value. */
  text: string;
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** `detail` is the short second line; `full` the sentence for the tooltip (default: the detail). */
function view(kind: UsageKind, label: string, detail: string, full = detail): UsageView {
  return { kind, label, detail: capitalize(detail), text: `${label}: ${full}` };
}

/**
 * What the Usage column says. "Unknown" is never shown like "no finding": the
 * rule would judge the app but the data cannot tell (D6, docs/rules.md).
 * `usage` is undefined in reports written before the rule existed.
 */
export function usageView(usage: AppUsage | null | undefined): UsageView {
  if (usage === null || usage === undefined) {
    return { kind: 'none', label: '—', detail: '', text: '—' };
  }
  switch (usage.state) {
    case 'idle':
      return view(
        'idle',
        'Looks unused',
        `${SIGNAL_SHORT[usage.signal]} (${usage.confidence})`,
        `${SIGNAL_TEXT[usage.signal]}, ${CONFIDENCE_TEXT[usage.confidence]}`,
      );
    case 'active':
      return view(
        'active',
        'In use',
        `last request ${formatDate(usage.lastRequestAt)}`,
        `last request ${formatDateTime(usage.lastRequestAt)}`,
      );
    case 'unknown':
      return view('unknown', 'Unknown', REASON_TEXT[usage.reason]);
    case 'not_assessed':
      return view('not_assessed', 'Not judged', REASON_TEXT[usage.reason]);
  }
}

const RANK: Record<UsageKind, number> = {
  idle: 4,
  unknown: 3,
  active: 2,
  not_assessed: 1,
  none: 0,
};

/** Sort order of the Usage column: unused first, then unknown, in use, not judged. */
export function usageRank(usage: AppUsage | null | undefined): number {
  return RANK[usageView(usage).kind];
}

/**
 * The hint under the Idle apps key figure: each signal with its confidence,
 * then how many apps could not be told, e.g.
 * "1 no route (high) · 1 no traffic (medium) · 2 unknown".
 */
export function idleHint(apps: readonly AppInventoryItem[]): string {
  const parts = new Map<string, number>();
  let unknown = 0;
  for (const { usage } of apps) {
    if (usage?.state === 'idle') {
      const key = `${SIGNAL_SHORT[usage.signal]} (${usage.confidence})`;
      parts.set(key, (parts.get(key) ?? 0) + 1);
    } else if (usage?.state === 'unknown') {
      unknown += 1;
    }
  }
  const texts = [...parts].map(([key, n]) => `${n} ${key}`);
  if (unknown > 0) texts.push(`${unknown} unknown`);
  return texts.length > 0 ? texts.join(' · ') : 'no app looks unused';
}
