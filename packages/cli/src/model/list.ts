import { z } from 'zod';

/**
 * A list of at most `max` elements, each parsed with `element`, that stops at
 * its first invalid element (docs/security-review.md SEC-21).
 *
 * `z.array` parses every element and keeps one issue per invalid one, so a
 * crafted snapshot with a million `{}` in a list builds millions of issues
 * before failing, and nested lists multiply that. Here a list that is too
 * long is refused before any element is read, and an invalid element ends
 * the list with its own issues only. However many elements are wrong, a
 * snapshot yields at most the issues of one element per list. Valid elements
 * are parsed exactly as `z.array(element)` would: defaults applied, unknown
 * keys dropped.
 *
 * Every list a snapshot can hold is built with this function; `eslint.config.js`
 * refuses `z.array` in `src/model`.
 */
export function list<T extends z.ZodType>(element: T, max: number) {
  // eslint-disable-next-line no-restricted-syntax -- the one array of the model, and its elements are only counted
  return z
    .array(z.unknown())
    .max(max)
    .transform((items, ctx): z.output<T>[] => {
      const parsed: z.output<T>[] = [];
      for (let index = 0; index < items.length; index++) {
        const item = items[index];
        const result = element.safeParse(item);
        if (!result.success) {
          for (const issue of result.error.issues) {
            // A finished issue has its message set, and zod keeps a message
            // it finds, so the issue is raised again as it is, one level up.
            // Its type would want the input the issue was raised on, which
            // zod dropped; the element stands in, and zod drops it again.
            const raised = { ...issue, input: item, path: [index, ...issue.path] };
            ctx.issues.push(raised as z.core.$ZodRawIssue);
          }
          return z.NEVER;
        }
        parsed.push(result.data);
      }
      return parsed;
    });
}

/**
 * The longest each list of a snapshot may be. Each one is set above what a
 * real snapshot can hold before the file limits in `snapshot.ts` stop it
 * (128 MB, or about 4 million values: some 42,000 apps as a scan writes
 * them), so for a real snapshot the file limits are the ones that apply.
 * These stop a crafted file from packing one list with millions of tiny
 * elements. The lists inside a project record have their own, lower limits
 * in `raw.ts`, set by what the project collector keeps.
 */
export const SNAPSHOT_LIST_LIMITS = {
  /** A scan reads one org. */
  orgs: 100,
  spaces: 50_000,
  apps: 100_000,
  /** One current droplet per app. */
  droplets: 100_000,
  /** One `web` process per app, two during a rolling deployment. */
  processes: 200_000,
  /** Routes can outnumber apps: a multitenant approuter has one per subscriber. */
  routes: 1_000_000,
  /** Cloud Foundry allows 100 destinations per route (docs/data-sources.md §9.1). */
  routeDestinations: 1_000,
  /** One entry per app with an HTTP route. */
  traffic: 100_000,
  /** Apps out of a scan's sight keep their entry. */
  history: 200_000,
  /** A project scan writes one. */
  projects: 1_000,
  findings: 1_000_000,
  checks: 1_000,
  /** Buildpacks of one app or droplet. */
  buildpacks: 100,
  /** References of one finding. */
  references: 100,
  /** Roles of one check or rule, OWASP categories of one rule (there are 4 and 10). */
  tags: 10,
  /** Rules in the report data. */
  rules: 1_000,
} as const;
