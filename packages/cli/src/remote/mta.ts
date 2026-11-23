import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  MTA_NAME_PATTERN,
  MTA_NAMESPACE_PATTERN,
  MTA_VERSION_PATTERN,
  PROJECT_ID_PATTERN,
} from '../model/raw.js';

/*
 * Deployed MTA projects, as far as the app list of a space tells them
 * (docs/data-sources.md §11). The deploy service behind `cf deploy`
 * (cloudfoundry/multiapps-controller: `MtaMetadataBuilder`,
 * `ApplicationMetadataBuilder`) marks every app of a multi-target application
 * with labels and annotations. This module reads six of them, groups the apps
 * of a space by project, words the entries of the picker and derives the
 * project id each app is reported under. Pure functions: no request, no file,
 * no clock.
 *
 * Whoever may update an app can set these values (`PATCH /v3/apps/:guid`,
 * Space Developer), so the grouping is a display aid, not a trust boundary:
 * a value is used only when it matches its pattern, and every other label
 * and annotation is dropped when the app is parsed, because annotations can
 * hold personal data.
 */

/** The most apps of one project that one run reads; a larger project is read app by app with --app. */
export const MAX_PROJECT_APPS = 50;
/** How many app names a picker entry lists before it says "and N more". */
const MAX_APPS_LISTED = 10;
/** The label values: lower-case hex MD5 digests (`MtaMetadataUtil.getHashedLabel`). */
const MD5_HEX = /^[0-9a-f]{32}$/;
/** `mta_module` is a small JSON object; a longer value is not one the deploy service wrote. */
const MAX_MODULE_JSON = 512;
const PROJECT_ID_MAX = 64;
const SLUG_MAX = 48;
const HASH_HEX = 8;

/** The `name` of an `mta_module` annotation (`{"name":"<module>"}`), when it is a plain name. */
function moduleName(json: string): string | undefined {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || !Object.hasOwn(value, 'name')) {
    return undefined;
  }
  const name = (value as { name: unknown }).name;
  return typeof name === 'string' && MTA_NAME_PATTERN.test(name) ? name : undefined;
}

/** A value that is kept when it matches its pattern and left out otherwise; it never fails the app. */
const text = (pattern: RegExp) => z.string().regex(pattern).optional().catch(undefined);

/**
 * Stands for a namespace key that is there with a value that cannot be used
 * (a wrong type, `null`, a pattern mismatch). It only ever makes the app an
 * app on its own (`mtaIdentity`); it is never shown or stored.
 */
export const UNUSABLE_NAMESPACE: unique symbol = Symbol('unusable namespace');

/**
 * A namespace key: left out when it is absent, kept when it matches its
 * pattern, marked otherwise. Unlike the other keys an unusable one is not
 * simply left out: an app with a namespace key is not part of the deployment
 * without a namespace, whatever the key holds. It never fails the app.
 */
const namespaceKey = (pattern: RegExp) =>
  z
    .unknown()
    .transform((value) =>
      typeof value === 'string' && pattern.test(value) ? value : UNUSABLE_NAMESPACE,
    )
    .optional();

/**
 * The only keys read of an app's `metadata`. Nothing here can fail: a wrong
 * type, `null`, a value that does not match or a missing `metadata` leaves
 * the key out (a namespace key is marked as unusable instead), because the CF
 * client drops a resource that fails its schema and the app would vanish from
 * the list.
 */
export const MtaMetadataSchema = z
  .object({
    labels: z.object({ mta_id: text(MD5_HEX), mta_namespace: namespaceKey(MD5_HEX) }).catch({}),
    annotations: z
      .object({
        mta_id: text(MTA_NAME_PATTERN),
        mta_version: text(MTA_VERSION_PATTERN),
        mta_namespace: namespaceKey(MTA_NAMESPACE_PATTERN),
        /** Parsed: the module name, not the JSON text. */
        mta_module: z
          .string()
          .max(MAX_MODULE_JSON)
          .transform(moduleName)
          .optional()
          .catch(undefined),
      })
      .catch({}),
  })
  .catch({ labels: {}, annotations: {} });
export type MtaMetadata = z.infer<typeof MtaMetadataSchema>;

/** An app as this module needs it. */
export interface MtaApp {
  name: string;
  metadata: MtaMetadata;
}

/** The MTA an app was deployed from; every value has passed its pattern. */
export interface MtaIdentity {
  id: string;
  version: string | null;
  module: string | null;
  /** null for a deployment without a namespace. */
  namespace: string | null;
}

export interface MtaMember<T extends MtaApp> {
  app: T;
  mta: MtaIdentity;
}

/** One deployment of an MTA: an id and a namespace, or none. */
export interface MtaProject<T extends MtaApp> {
  id: string;
  namespace: string | null;
  /** In the order of the app list (by name). */
  members: MtaMember<T>[];
}

/** The label the deploy service derives from a value: its lower-case hex MD5 (UTF-8). */
export function hashedLabel(value: string): string {
  return createHash('md5').update(value, 'utf8').digest('hex');
}

/**
 * The MTA an app belongs to, or null for an app on its own. The app belongs
 * when its `mta_id` label is the MD5 of its `mta_id` annotation, as the
 * deploy service writes them, and the namespace is consistent: no namespace
 * key at all, or a valid annotation and a label that is its MD5. A namespace
 * key with any other value makes the app an app on its own.
 */
export function mtaIdentity(metadata: MtaMetadata): MtaIdentity | null {
  const { labels, annotations } = metadata;
  const id = annotations.mta_id;
  if (id === undefined || labels.mta_id !== hashedLabel(id)) return null;
  const namespace = annotations.mta_namespace;
  const label = labels.mta_namespace;
  if (namespace === UNUSABLE_NAMESPACE || label === UNUSABLE_NAMESPACE) return null;
  const expected = namespace === undefined ? undefined : hashedLabel(namespace);
  if (label !== expected) return null;
  return {
    id,
    version: annotations.mta_version ?? null,
    module: annotations.mta_module ?? null,
    namespace: namespace ?? null,
  };
}

/** By code point; the values compared are ASCII identifiers. */
function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Groups apps by the deployment they belong to. Projects are sorted by id,
 * then by namespace (the deployment without one first); their apps and the
 * apps on their own keep the order given.
 */
export function groupByMta<T extends MtaApp>(
  apps: readonly T[],
): { projects: MtaProject<T>[]; singles: T[] } {
  const byKey = new Map<string, MtaProject<T>>();
  const singles: T[] = [];
  for (const app of apps) {
    const mta = mtaIdentity(app.metadata);
    if (mta === null) {
      singles.push(app);
      continue;
    }
    const key = JSON.stringify([mta.id, mta.namespace]);
    const project = byKey.get(key) ?? { id: mta.id, namespace: mta.namespace, members: [] };
    project.members.push({ app, mta });
    byKey.set(key, project);
  }
  const projects = [...byKey.values()].sort(
    (a, b) => compareText(a.id, b.id) || compareText(a.namespace ?? '', b.namespace ?? ''),
  );
  return { projects, singles };
}

/** The version every app of the project carries, or null when they differ or one has none. */
export function projectVersion<T extends MtaApp>(project: MtaProject<T>): string | null {
  const versions = new Set(project.members.map((member) => member.mta.version));
  const [version] = versions;
  return versions.size === 1 && version !== undefined ? version : null;
}

/** A deployment among others of the same id: "without a namespace" or "namespace <name>". */
export function deploymentName(namespace: string | null): string {
  return namespace === null ? 'without a namespace' : `namespace ${namespace}`;
}

/** `<id>[ <version>][ (namespace <ns>)]`. */
export function projectTitle<T extends MtaApp>(project: MtaProject<T>): string {
  const version = projectVersion(project);
  return (
    project.id +
    (version === null ? '' : ` ${version}`) +
    (project.namespace === null ? '' : ` (${deploymentName(project.namespace)})`)
  );
}

/**
 * The picker entry of a project: its title, how many of its apps will be
 * read, and their names with the module each was built from.
 */
export function projectLabel<T extends MtaApp>(
  project: MtaProject<T>,
  isReady: (app: T) => boolean,
): string {
  const ready = project.members.filter((member) => isReady(member.app));
  const total = project.members.length;
  const count = ready.length === total ? `${total} app(s)` : `${ready.length} of ${total} apps`;
  const names = ready
    .slice(0, MAX_APPS_LISTED)
    .map(({ app, mta }) => (mta.module === null ? app.name : `${app.name} (${mta.module})`));
  const more = ready.length - names.length;
  return `${projectTitle(project)} · project, ${count}: ${names.join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
}

/** Whether the project has more apps than one run reads. */
export function overAppLimit<T extends MtaApp>(project: MtaProject<T>): boolean {
  return project.members.length > MAX_PROJECT_APPS;
}

/** Why a project over the limit is not read as a whole, as the words after its name. */
export function overAppLimitWhy(apps: number): string {
  return `it has ${apps} apps, more than the ${MAX_PROJECT_APPS} one run reads; read one app with --app <name>`;
}

/** An id for a name that is not one: what is left of the name, and 8 hex digits of its SHA-256. */
function slugId(name: string): string {
  const slug = name
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, SLUG_MAX);
  const hash = createHash('sha256').update(name, 'utf8').digest('hex').slice(0, HASH_HEX);
  return `${slug === '' ? 'app' : slug}-${hash}`;
}

/** The id an app name gives on its own: the name when it is a valid id, else what `slugId` makes of it. */
export function projectIdOf(name: string): string {
  return PROJECT_ID_PATTERN.test(name) ? name : slugId(name);
}

/** The candidate, or the candidate with `-2`, `-3`, … (cut so that it stays an id) while it is taken. */
function freeId(candidate: string, isTaken: (id: string) => boolean): string {
  let id = candidate;
  for (let n = 2; isTaken(id); n += 1) {
    const suffix = `-${n}`;
    id = `${candidate.slice(0, PROJECT_ID_MAX - suffix.length)}${suffix}`;
  }
  return id;
}

/**
 * The project id of each app of a run, in the order given: the app name when
 * it is a valid id, else a readable rest of the name with a hash of the whole
 * name, so that the id stays the same when a deploy recreates the app. Ids
 * are unique within the run, because findings, inventory rows and check ids
 * are keyed by them: an id that is taken gets `-2`, `-3`, … An app whose
 * name is a valid id is always reported under that name; a derived id never
 * takes it.
 */
export function withProjectIds<T>(
  items: readonly T[],
  nameOf: (item: T) => string,
): { item: T; id: string }[] {
  const own = new Set(items.map(nameOf).filter((name) => PROJECT_ID_PATTERN.test(name)));
  const given = new Set<string>();
  return items.map((item) => {
    const name = nameOf(item);
    const id = freeId(
      projectIdOf(name),
      (candidate) => given.has(candidate) || (candidate !== name && own.has(candidate)),
    );
    given.add(id);
    return { item, id };
  });
}
