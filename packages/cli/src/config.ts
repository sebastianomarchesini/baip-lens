import { z } from 'zod';
import { toApiEndpoint } from './guided/regions.js';
import { ConfigError } from './http/errors.js';
import { MTA_NAME_PATTERN, MTA_NAMESPACE_PATTERN } from './model/raw.js';
import { SEVERITIES, type Severity } from './model/severity.js';
import { type ReportFormat, parseFormats } from './reporters/index.js';

export const FAIL_ON_VALUES = ['none', ...SEVERITIES] as const;
export type FailOn = (typeof FAIL_ON_VALUES)[number];

export const ApiUrlSchema = z
  .string()
  .trim()
  .transform((input, ctx) => {
    const value = toApiEndpoint(input);
    try {
      const url = new URL(/^[a-z]+:\/\//i.test(value) ? value : `https://${value}`);
      if (url.protocol !== 'https:') {
        ctx.addIssue({ code: 'custom', message: '--api must use https' });
        return z.NEVER;
      }
      if (url.username || url.password || url.search || url.hash) {
        ctx.addIssue({
          code: 'custom',
          message: '--api must be a plain URL like https://api.cf.eu10.hana.ondemand.com',
        });
        return z.NEVER;
      }
      return url;
    } catch {
      ctx.addIssue({ code: 'custom', message: `--api is not a valid URL: ${value}` });
      return z.NEVER;
    }
  });

const FailOnSchema = z.enum(FAIL_ON_VALUES, {
  error: () => `--fail-on must be one of: ${FAIL_ON_VALUES.join(', ')}`,
});

const FormatsSchema = z.string().transform((value, ctx): ReportFormat[] => {
  try {
    return parseFormats(value);
  } catch (error) {
    ctx.addIssue({
      code: 'custom',
      message: error instanceof Error ? error.message : String(error),
    });
    return z.NEVER;
  }
});

const CommonSchema = z.object({
  out: z.string().min(1),
  format: FormatsSchema,
  failOn: FailOnSchema,
});

export const ScanConfigSchema = CommonSchema.extend({
  api: ApiUrlSchema,
  org: z.string().trim().min(1, '--org is required'),
  space: z.string().trim().min(1).optional(),
  deep: z.boolean(),
  probeRoutes: z.boolean(),
  concurrency: z.coerce
    .number({ error: () => '--concurrency must be a number' })
    .int('--concurrency must be a whole number')
    .min(1, '--concurrency must be at least 1')
    .max(20, '--concurrency must be at most 20'),
  /** `--no-traffic-check` sets this to false. */
  trafficCheck: z.boolean(),
  /** Hours; D5 sets the default to 12. A month is the most Log Cache could ever hold. */
  minTrafficWindow: z.coerce
    .number({ error: () => '--min-traffic-window must be a number of hours' })
    .positive('--min-traffic-window must be more than 0 hours')
    .max(720, '--min-traffic-window must be at most 720 hours'),
  trafficPages: z.coerce
    .number({ error: () => '--traffic-pages must be a number' })
    .int('--traffic-pages must be a whole number')
    .min(1, '--traffic-pages must be at least 1')
    .max(20, '--traffic-pages must be at most 20'),
  /** `--previous`: an earlier snapshot of the same org whose traffic history is carried forward. */
  previous: z.string().trim().min(1, '--previous needs a snapshot file').optional(),
  quiet: z.boolean(),
});
export type ScanConfig = z.infer<typeof ScanConfigSchema>;

export const ReportConfigSchema = CommonSchema.extend({
  from: z.string().min(1, '--from is required'),
});
export type ReportConfig = z.infer<typeof ReportConfigSchema>;

/** The options that only mean something with --cf, each with the flag as the user types it. */
const CF_ONLY_FLAGS = [
  ['app', '--app'],
  ['mta', '--mta'],
  ['mtaNamespace', '--mta-namespace'],
  ['api', '--api'],
  ['org', '--org'],
  ['space', '--space'],
] as const;

export const ProjectConfigSchema = CommonSchema.extend({
  /** A local project folder. */
  path: z.string().min(1, '--path is required').optional(),
  /** Read a deployed app instead (`--cf`). */
  cf: z.boolean().default(false),
  app: z.string().trim().min(1, '--app needs an app name').optional(),
  /** Read every app of this deployed project (MTA); only a value an MTA id can have is accepted. */
  mta: z
    .string()
    .trim()
    .regex(MTA_NAME_PATTERN, '--mta needs a project id (letters, digits, ".", "_" and "-")')
    .optional(),
  /** Which deployment of the project; the empty string is the one without a namespace. */
  mtaNamespace: z
    .string()
    .refine((value) => value === '' || MTA_NAMESPACE_PATTERN.test(value), {
      error:
        '--mta-namespace needs a namespace (at most 36 letters, digits, ".", "_" and "-"), or "" for the deployment without one',
    })
    .optional(),
  api: ApiUrlSchema.optional(),
  org: z.string().trim().min(1, '--org needs an org name').optional(),
  space: z.string().trim().min(1, '--space needs a space name').optional(),
  quiet: z.boolean(),
}).superRefine((value, ctx) => {
  if (value.cf && value.path !== undefined) {
    ctx.addIssue({
      code: 'custom',
      message: 'Use either --path (a local folder) or --cf (a deployed app), not both.',
    });
  }
  if (!value.cf && value.path === undefined) {
    ctx.addIssue({
      code: 'custom',
      message: "required option '--path <dir>' not specified (or use --cf to read a deployed app)",
    });
  }
  if (!value.cf) {
    for (const [key, flag] of CF_ONLY_FLAGS) {
      if (value[key] !== undefined) {
        ctx.addIssue({ code: 'custom', message: `${flag} works only together with --cf` });
      }
    }
  }
  if (value.app !== undefined && value.mta !== undefined) {
    ctx.addIssue({
      code: 'custom',
      message: 'Use either --app (one app) or --mta (every app of a project), not both.',
    });
  }
  if (value.mtaNamespace !== undefined && value.mta === undefined) {
    ctx.addIssue({ code: 'custom', message: '--mta-namespace works only together with --mta' });
  }
});
export type ProjectConfig = z.infer<typeof ProjectConfigSchema>;

function parseOrThrow<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ConfigError(result.error.issues.map((i) => i.message).join('\n'));
  }
  return result.data;
}

export const parseScanConfig = (input: unknown): ScanConfig =>
  parseOrThrow(ScanConfigSchema, input);
export const parseReportConfig = (input: unknown): ReportConfig =>
  parseOrThrow(ReportConfigSchema, input);
export const parseProjectConfig = (input: unknown): ProjectConfig =>
  parseOrThrow(ProjectConfigSchema, input);

export function failThreshold(failOn: FailOn): Severity | undefined {
  return failOn === 'none' ? undefined : failOn;
}

/** Parses a CF API endpoint the way --api does (https only, no query, no credentials). */
export function parseApiUrl(value: string): URL {
  return parseOrThrow(ApiUrlSchema, value);
}
