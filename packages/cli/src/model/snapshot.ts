import { z } from 'zod';
import { CfRoleSchema, CheckResultSchema } from './check.js';
import { FindingSchema } from './finding.js';
import { OwaspCategorySchema } from './owasp.js';
import { LifecycleTypeSchema, RawDataSchema } from './raw.js';
import { SeveritySchema } from './severity.js';

export const SNAPSHOT_SCHEMA_VERSION = 1;

const Timestamp = z.iso.datetime({ offset: true });

const SeverityCountsSchema = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
});
export type SeverityCounts = z.infer<typeof SeverityCountsSchema>;

export const InventoryKindSchema = z.enum(['app', 'project']);
export type InventoryKind = z.infer<typeof InventoryKindSchema>;

/** How sure an `APP_IDLE` verdict is; also recorded in the finding's evidence. */
export const ConfidenceSchema = z.enum(['high', 'medium', 'low']);
export type Confidence = z.infer<typeof ConfidenceSchema>;

/** Which evidence made an app look unused. */
export const UsageSignalSchema = z.enum([
  /** Started, with a web instance, and no route at all. */
  'no_route',
  /** No router access log in the window Log Cache held. */
  'no_traffic',
  /** Stopped for more than 90 days. */
  'stopped',
]);
export type UsageSignal = z.infer<typeof UsageSignalSchema>;

/** Why the rule could not tell: it would judge the app, but the data does not allow it. */
export const UsageUnknownReasonSchema = z.enum([
  /** Has an HTTP route, and the scan did not include the traffic check (an older snapshot). */
  'traffic_not_checked',
  /** Has an HTTP route, and the traffic check was turned off (`--no-traffic-check`). */
  'traffic_check_off',
  /** Has an HTTP route, and Log Cache could not be read for it (404, unavailable, error). */
  'traffic_unreadable',
  /** Log Cache held less history for the app than `--min-traffic-window` (D5). */
  'window_too_short',
  /** Only TCP, internal-domain or unclassified routes: they leave no router log (D6). */
  'traffic_not_measurable',
  /** The routes or processes collector did not run. */
  'data_unavailable',
]);
export type UsageUnknownReason = z.infer<typeof UsageUnknownReasonSchema>;

/** Why the rule does not judge this app at all, by design. */
export const UsageNotAssessedReasonSchema = z.enum([
  'stopped',
  /** No `web` process, or `web` scaled to 0: a worker or a job. */
  'no_web_instance',
  /** The `web` process uses the `process` health check, which CF documents for workers. */
  'worker_health_check',
]);
export type UsageNotAssessedReason = z.infer<typeof UsageNotAssessedReasonSchema>;

/**
 * Whether an app looks used (`APP_IDLE`). `idle` always has a matching
 * finding. `unknown` is not "no finding": the rule would judge the app but
 * the data cannot tell, and the report shows it as such.
 */
export const AppUsageSchema = z.discriminatedUnion('state', [
  z.object({ state: z.literal('idle'), signal: UsageSignalSchema, confidence: ConfidenceSchema }),
  /** A router access log was seen inside the window: no finding. */
  z.object({ state: z.literal('active'), lastRequestAt: Timestamp }),
  z.object({ state: z.literal('unknown'), reason: UsageUnknownReasonSchema }),
  z.object({ state: z.literal('not_assessed'), reason: UsageNotAssessedReasonSchema }),
]);
export type AppUsage = z.infer<typeof AppUsageSchema>;

export const AppInventoryItemSchema = z.object({
  guid: z.string(),
  name: z.string(),
  org: z.string(),
  space: z.string(),
  /** A CF app, or a local project scanned with `baip-lens project`. Missing in 0.1 snapshots. */
  kind: InventoryKindSchema.default('app'),
  /** null for projects. */
  state: z.enum(['STARTED', 'STOPPED']).nullable(),
  lifecycleType: LifecycleTypeSchema,
  stack: z.string().nullable(),
  buildpacks: z.array(z.object({ name: z.string(), version: z.string().nullable() })),
  createdAt: Timestamp.nullable(),
  updatedAt: Timestamp.nullable(),
  /** When the current droplet was staged; null when unknown or not visible. */
  lastDeployAt: Timestamp.nullable(),
  /** `APP_IDLE` assessment; null when the rule was not part of the scan (projects, older snapshots). */
  usage: AppUsageSchema.nullable().default(null),
  findingCounts: SeverityCountsSchema,
  highestSeverity: SeveritySchema.nullable(),
  /** Weighted sum of findings, used to sort apps by risk (see docs/rules.md). */
  riskScore: z.number().nonnegative(),
});
export type AppInventoryItem = z.infer<typeof AppInventoryItemSchema>;

export const RuleMetaSchema = z.object({
  id: z.string().regex(/^[A-Z0-9_]+$/),
  title: z.string(),
  description: z.string(),
  roles: z.array(CfRoleSchema),
  /** OWASP Top 10 (2025) categories the rule maps to. */
  owasp: z.array(OwaspCategorySchema),
  helpUri: z.url(),
});
export type RuleMeta = z.infer<typeof RuleMetaSchema>;

export const ScopeSchema = z.object({
  /** Absent for a project scan. */
  apiEndpoint: z.url().optional(),
  orgs: z.array(z.string()),
  spaces: z.array(z.string()).optional(),
  /** Ids of the local projects scanned with `baip-lens project`. */
  projects: z.array(z.string()).optional(),
});

export const ScanOptionsSchema = z.object({
  deep: z.boolean(),
  probeRoutes: z.boolean(),
  /**
   * Whether the scan asked Log Cache for traffic: on unless `--no-traffic-check`.
   * Whether it could read it is the status of `collect.traffic`. False in
   * snapshots written before the option existed, which read no traffic.
   */
  trafficCheck: z.boolean().default(false),
  /** `--min-traffic-window`: less history than this gives `unknown`, never a finding (D5). */
  minTrafficWindowHours: z.number().positive().default(12),
  /** `--traffic-pages`: pages of up to 1000 LOG envelopes read per app, newest first. */
  trafficPages: z.number().int().positive().default(5),
  /** `--previous`: when the scan whose traffic history this one carries forward ran. */
  previousScannedAt: Timestamp.nullable().default(null),
});
/** The scan options a snapshot records; the analyzers read them, offline too. */
export type SnapshotOptions = z.infer<typeof ScanOptionsSchema>;

export const DEFAULT_SNAPSHOT_OPTIONS: SnapshotOptions = {
  deep: false,
  probeRoutes: false,
  trafficCheck: false,
  minTrafficWindowHours: 12,
  trafficPages: 5,
  previousScannedAt: null,
};

export const SnapshotSchema = z.object({
  schemaVersion: z.literal(SNAPSHOT_SCHEMA_VERSION),
  tool: z.object({ name: z.string(), version: z.string() }),
  scannedAt: Timestamp,
  scope: ScopeSchema,
  options: ScanOptionsSchema,
  checks: z.array(CheckResultSchema),
  raw: RawDataSchema,
  apps: z.array(AppInventoryItemSchema),
  findings: z.array(FindingSchema),
});
export type Snapshot = z.infer<typeof SnapshotSchema>;

/**
 * What the reports (JSON, HTML) carry: the snapshot without the raw data,
 * plus precomputed summary counts.
 */
export const ReportDataSchema = SnapshotSchema.omit({ raw: true }).extend({
  /** Metadata for every rule known to this tool version. */
  rules: z.array(RuleMetaSchema),
  summary: z.object({
    /** Inventory items of kind `app`. */
    apps: z.number().int().nonnegative(),
    /** Inventory items of kind `project`. */
    projects: z.number().int().nonnegative(),
    findings: z.number().int().nonnegative(),
    findingsBySeverity: SeverityCountsSchema,
    checksSkipped: z.number().int().nonnegative(),
  }),
});
export type ReportData = z.infer<typeof ReportDataSchema>;
