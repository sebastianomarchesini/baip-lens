import { z } from 'zod';
import { describeUrl } from '../net/errors.js';
import type { TokenProvider } from './auth.js';
import { HttpBodyTooLargeError, HttpNetworkError } from './errors.js';
import type { ReadOnlyHttp } from './httpClient.js';

/**
 * A Log Cache read that did not return envelopes. `status` is the HTTP status,
 * or `network` when nothing came back. Log Cache answers 404, never 401 or 403,
 * for a missing role, an invalid token or a failed permission lookup, and 429
 * for a response that is too large (docs/data-sources.md §9.3, §9.5).
 */
export class LogCacheError extends Error {
  override readonly name = 'LogCacheError';

  constructor(
    readonly status: number | 'network',
    url: URL,
    detail?: string,
  ) {
    const what = status === 'network' ? 'network error' : `HTTP ${status}`;
    super(`Log Cache ${what} for ${describeUrl(url)}${detail ? `: ${detail}` : ''}`);
  }
}

/**
 * One envelope as far as BAIP Lens reads it. Everything else in the envelope,
 * the access-log line (`log.payload`) above all, is never parsed or kept.
 */
export interface LogCacheEnvelope {
  /** Nanoseconds since the epoch, as Log Cache sends it: a decimal int64 string. */
  timestamp: string;
  /** A router access log: its `source_type` tag is `RTR`. */
  router: boolean;
  /** It carries a `source_type` tag at all (the value is not kept). */
  tagged: boolean;
}

export interface ReadQuery {
  /** Newest first; Log Cache's default is the oldest first. */
  descending?: boolean;
  envelopeTypes?: readonly 'LOG'[];
  limit: number;
  /** Exclusive upper bound: the raw timestamp of an envelope already read. */
  endTime?: string;
}

export interface ReadResult {
  envelopes: LogCacheEnvelope[];
  /** Envelopes without a usable timestamp, dropped. */
  invalid: number;
}

/** Log Cache rejects a larger `limit` with HTTP 500 instead of clamping it. */
export const MAX_LIMIT = 1000;
const MAX_BYTES = 16 * 1024 * 1024;
/** Source ids BAIP Lens asks for are app GUIDs. */
const SOURCE_ID = /^[A-Za-z0-9-]{1,64}$/;

/** Only the two values read; `z.object` drops every other key, the payload included. */
const EnvelopeSchema = z.object({
  timestamp: z.string().regex(/^\d{1,19}$/),
  tags: z.object({ source_type: z.string().optional() }).nullish(),
});

const ReadResponseSchema = z.object({
  envelopes: z.object({ batch: z.array(z.unknown()) }),
});

/**
 * Read-only Log Cache client. Like the CF client it is built on
 * `ReadOnlyHttp`, so it cannot send anything but GET, and the egress
 * allow-list only lets it reach `/api/v1/read/<guid>` on the host taken from
 * the CF root's `links.log_cache`.
 */
export class LogCacheClient {
  private readonly basePath: string;

  constructor(
    private readonly http: ReadOnlyHttp,
    readonly baseUrl: URL,
    private readonly tokens: TokenProvider,
  ) {
    this.basePath = baseUrl.pathname.replace(/\/+$/, '');
  }

  async read(sourceId: string, query: ReadQuery): Promise<ReadResult> {
    if (!SOURCE_ID.test(sourceId)) throw new Error('Invalid Log Cache source id');
    const url = new URL(`${this.basePath}/api/v1/read/${sourceId}`, this.baseUrl.origin);
    if (query.descending === true) url.searchParams.set('descending', 'true');
    // Repeated, never comma-separated: Log Cache reads a list as one unknown type.
    for (const type of query.envelopeTypes ?? []) url.searchParams.append('envelope_types', type);
    url.searchParams.set(
      'limit',
      String(Math.min(Math.max(1, Math.floor(query.limit)), MAX_LIMIT)),
    );
    if (query.endTime !== undefined) url.searchParams.set('end_time', query.endTime);

    let text: string;
    try {
      const res = await this.http.get({
        url,
        headers: { authorization: `bearer ${await this.tokens.getToken()}` },
        maxBytes: MAX_BYTES,
        retryOn: [502, 503, 504],
      });
      if (res.status !== 200) throw new LogCacheError(res.status, url);
      text = res.text;
    } catch (error) {
      if (error instanceof HttpNetworkError) throw new LogCacheError('network', url, error.code);
      if (error instanceof HttpBodyTooLargeError) {
        throw new LogCacheError(429, url, 'response too large');
      }
      throw error;
    }
    return parse(text, url);
  }
}

function parse(text: string, url: URL): ReadResult {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new LogCacheError(200, url, 'response is not valid JSON');
  }
  const page = ReadResponseSchema.safeParse(body);
  if (!page.success) throw new LogCacheError(200, url, 'unexpected response shape');
  const result: ReadResult = { envelopes: [], invalid: 0 };
  for (const item of page.data.envelopes.batch) {
    const envelope = EnvelopeSchema.safeParse(item);
    if (envelope.success) {
      const sourceType = envelope.data.tags?.source_type;
      result.envelopes.push({
        timestamp: envelope.data.timestamp,
        router: sourceType === 'RTR',
        tagged: sourceType !== undefined,
      });
    } else {
      result.invalid += 1;
    }
  }
  return result;
}
