import '@ui5/webcomponents-icons/dist/question-mark.js';
import type { AppUsage } from '@baip-lens/model';
import { Icon, ObjectStatus } from '@ui5/webcomponents-react';
import { usageView } from '../data/usage';

/**
 * The `APP_IDLE` verdict of one app, on two lines: the status, then the
 * signal and confidence, the reason or the last request in small secondary
 * text, with the whole sentence as tooltip. Idle uses the semantics of its
 * finding (Information); in use is Positive; unknown gets its own icon, so it
 * can never be read as "no finding"; not judged is plain secondary text.
 */
export function UsageStatus({ usage }: { usage: AppUsage | null | undefined }) {
  const view = usageView(usage);
  if (view.kind === 'none') return <span className="usage-not-judged">{view.label}</span>;
  const status =
    view.kind === 'idle' ? (
      <ObjectStatus state="Information" showDefaultIcon>
        {view.label}
      </ObjectStatus>
    ) : view.kind === 'active' ? (
      <ObjectStatus state="Positive" showDefaultIcon>
        {view.label}
      </ObjectStatus>
    ) : view.kind === 'unknown' ? (
      <ObjectStatus state="None" icon={<Icon name="question-mark" />}>
        {view.label}
      </ObjectStatus>
    ) : (
      <span className="usage-not-judged">{view.label}</span>
    );
  return (
    <span className="usage-cell" title={view.text}>
      {status}
      <span className="usage-detail">{view.detail}</span>
    </span>
  );
}
