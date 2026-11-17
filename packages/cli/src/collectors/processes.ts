import { z } from 'zod';
import type { CfClient } from '../http/cfClient.js';
import type { HealthCheckType, RawProcess } from '../model/raw.js';
import { type Collected, type Scope, scopeQuery } from './apps.js';

/**
 * Fields confirmed in docs/data-sources.md §9.2. `command` is the only field
 * redacted for auditors, and it is never read: it can hold credentials.
 */
const CfProcessSchema = z.object({
  guid: z.string(),
  type: z.string(),
  instances: z.number().int().nonnegative(),
  updated_at: z.iso.datetime({ offset: true }),
  health_check: z.object({ type: z.string().nullish() }).nullish(),
  relationships: z.object({
    app: z.object({ data: z.object({ guid: z.string() }) }),
  }),
});

/**
 * Cloud Controller still accepts the legacy type `none` and maps it to
 * `process` itself (`HEALTH_CHECK_TYPE_MAPPING` in `app_manifest_message.rb`),
 * so it is read the same way here.
 */
export function toHealthCheckType(type: string | null | undefined): HealthCheckType | null {
  if (type === null || type === undefined) return null;
  if (type === 'none') return 'process';
  return type === 'port' || type === 'http' || type === 'process' ? type : 'unknown';
}

/**
 * GET /v3/processes?types=web, filtered by org (or space). Any role; results
 * are visibility-filtered. An app can have two `web` processes during a
 * rolling deployment, so the analyzer looks at all of them.
 */
export async function collectWebProcesses(
  cf: CfClient,
  scope: Scope,
): Promise<Collected<RawProcess>> {
  const result = await cf.list('/v3/processes', CfProcessSchema, {
    ...scopeQuery(scope),
    types: 'web',
  });
  return {
    invalid: result.invalid,
    items: result.resources
      // The filter is applied again in case an API ignores `types`.
      .filter((process) => process.type === 'web')
      .map((process) => ({
        guid: process.guid,
        appGuid: process.relationships.app.data.guid,
        type: 'web' as const,
        instances: process.instances,
        healthCheckType: toHealthCheckType(process.health_check?.type),
        updatedAt: process.updated_at,
      })),
  };
}
