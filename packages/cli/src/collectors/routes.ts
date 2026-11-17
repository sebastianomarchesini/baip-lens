import { z } from 'zod';
import type { CfClient } from '../http/cfClient.js';
import type { RawRoute, RouteKind } from '../model/raw.js';
import type { Collected } from './apps.js';

/**
 * Fields confirmed in docs/data-sources.md §9.1. Destinations are embedded in
 * every route of the list response. Host, path, port and url are not read:
 * the rules only need to know whether an app is reachable, and how.
 */
const CfRouteSchema = z.object({
  guid: z.string(),
  protocol: z.string().nullish(),
  destinations: z.array(z.object({ app: z.object({ guid: z.string() }) })).nullish(),
  relationships: z.object({
    space: z.object({ data: z.object({ guid: z.string() }) }),
    domain: z.object({ data: z.object({ guid: z.string() }) }),
  }),
});
export type CfRoute = z.infer<typeof CfRouteSchema>;

/** Only the flag that sets an internal (container-to-container) domain apart. */
const CfDomainSchema = z.object({ guid: z.string(), internal: z.boolean().nullish() });

/**
 * Space GUIDs per request: 50 keep the query near 2 KB, well under common
 * proxy limits, even for orgs with hundreds of spaces.
 */
export const SPACES_PER_REQUEST = 50;

/**
 * A route on an internal domain still reports protocol `http` (§9.1), so the
 * domain decides first. A route whose domain was not returned, or does not
 * say whether it is internal, is `unknown`: it counts as reachable, but it is
 * never a candidate for the traffic check, so it can never look silent.
 */
export function routeKind(
  route: CfRoute,
  internalByDomain: ReadonlyMap<string, boolean>,
): RouteKind {
  if (route.protocol === 'tcp') return 'tcp';
  const internal = internalByDomain.get(route.relationships.domain.data.guid);
  if (internal === true) return 'internal';
  if (internal === false && route.protocol === 'http') return 'http';
  return 'unknown';
}

function chunked<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function internalFlags(domains: readonly unknown[]): Map<string, boolean> {
  const flags = new Map<string, boolean>();
  for (const item of domains) {
    const domain = CfDomainSchema.safeParse(item);
    if (domain.success && typeof domain.data.internal === 'boolean') {
      flags.set(domain.data.guid, domain.data.internal);
    }
  }
  return flags;
}

/**
 * GET /v3/routes?space_guids=…&include=domain, one paginated call per 50
 * spaces. Filtering by space rather than org also returns routes shared into a
 * scanned space from another org, so a shared route never looks like "no
 * route". Any role; results are visibility-filtered (never a 403).
 */
export async function collectRoutes(
  cf: CfClient,
  spaceGuids: readonly string[],
): Promise<Collected<RawRoute>> {
  const byGuid = new Map<string, RawRoute>();
  let invalid = 0;
  // Sorted, so the requests do not depend on the order the API listed the spaces in.
  for (const spaces of chunked([...spaceGuids].sort(), SPACES_PER_REQUEST)) {
    const result = await cf.list('/v3/routes', CfRouteSchema, {
      space_guids: spaces.join(','),
      include: 'domain',
    });
    invalid += result.invalid;
    const internalByDomain = internalFlags(result.included.domains ?? []);
    for (const route of result.resources) {
      // A route shared into two spaces of different chunks comes back twice.
      byGuid.set(route.guid, {
        guid: route.guid,
        spaceGuid: route.relationships.space.data.guid,
        kind: routeKind(route, internalByDomain),
        // One app can be a destination several times (process types, ports).
        appGuids: [...new Set((route.destinations ?? []).map((d) => d.app.guid))].sort(),
      });
    }
  }
  return { items: [...byGuid.values()], invalid };
}
