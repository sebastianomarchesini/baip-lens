/*
 * What the two lookups of the lockfile packages share (docs/data-sources.md
 * §12.3, §12.4): the list of packages they ask about, and the pool that runs
 * their requests. Nothing here makes a request itself.
 */

/** A package version to look up: one the lockfile step kept, so one from the public npm registry. */
export interface PackageRef {
  name: string;
  version: string;
}

/** Order by code point, the same on every machine. */
export function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The distinct package versions, sorted by name and then version, in code point order. */
export function distinctPackages(packages: readonly PackageRef[]): PackageRef[] {
  const seen = new Set<string>();
  const distinct: PackageRef[] = [];
  for (const { name, version } of packages) {
    // A name holds no blank, so the key cannot stand for two packages.
    const key = `${name} ${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    distinct.push({ name, version });
  }
  return distinct.sort((a, b) => compareText(a.name, b.name) || compareText(a.version, b.version));
}

/** True once the lookup has failed: work that is under way starts no further request. */
export type Stopped = () => boolean;

export const NEVER_STOPPED: Stopped = () => false;

/**
 * Runs `work` on every item, at most `size` at a time. After the first
 * failure no further item is started; the ones in flight are waited for, and
 * the first failure is thrown. Work that makes more than one request asks
 * `stopped` before each further one.
 */
export async function inPool<T>(
  items: readonly T[],
  size: number,
  work: (item: T, stopped: Stopped) => Promise<void>,
): Promise<void> {
  let next = 0;
  let failed = false;
  let failure: unknown;
  const stopped: Stopped = () => failed;
  const worker = async (): Promise<void> => {
    while (!failed && next < items.length) {
      const item = items[next++] as T;
      try {
        await work(item, stopped);
      } catch (error) {
        if (!failed) failure = error;
        failed = true;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, worker));
  if (failed) throw failure;
}
